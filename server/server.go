// Copyright (c) Cathexis Development
// SPDX-License-Identifier: GPL-2.0-only
//
// server/server.go — Core P10 server for Acid.
//
// Manages the TLS connection to Cathexis, P10 link registration,
// BURST sequence, pseudo-client lifecycle, and the main read loop.
// All incoming P10 lines are parsed through ircv3.ParseP10Line() for
// tag-aware dispatch. All outgoing lines go through SendP10() for
// automatic IRCv3 tag injection.

package server

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/brandontroidl/noesis/config"
	"github.com/brandontroidl/noesis/ircv3"
	"github.com/brandontroidl/noesis/network"
	"github.com/brandontroidl/noesis/p10"
	"github.com/brandontroidl/noesis/store"
)

// Server is the core Acid P10 services server.
type Server struct {
	config  *config.Config
	conn    net.Conn
	reader  *bufio.Reader
	writer  *bufio.Writer
	writeMu sync.Mutex

	// P10 identity
	serverNumeric string
	numerics      *p10.NumericAllocator

	// Network state
	network *network.State

	// IRCv3 state
	batches     *ircv3.BatchTracker
	msgHandlers map[string]MessageHandler

	// Pseudo-client tracking
	pseudoMu      sync.RWMutex
	pseudoClients map[string]*PseudoClient

	// S2S authentication
	crypto *S2SCrypto

	// Event hooks for modules
	hooks *HookManager

	// Rate limiting
	limiter *RateLimiter

	// Message history store (chathistory)
	messages *store.MessageStore

	// Quote store
	quotes *store.QuoteStore

	// Module registry
	modules []Module

	// Burst state
	burstDone bool

	// Shutdown coordination
	shutdown chan struct{}
	done     chan struct{}
	running  bool

	// Per-message HMAC signing (activated after link registration)
	hmacActive bool
}

// Module is the interface that all Acid service modules implement.
type Module interface {
	Name() string
	Init(s *Server) error
	HandleMessage(s *Server, msg *ircv3.P10Message)
	Shutdown()
}

// PseudoClient represents a service bot pseudo-client on the network.
type PseudoClient struct {
	Numeric string
	Nick    string
	Ident   string
	Host    string
	Gecos   string
	Modes   string
	Module  Module // owning module
}

// New creates a new Acid server from the configuration.
func New(cfg *config.Config) (*Server, error) {
	serverNum := cfg.Server.Numeric
	maxClients := cfg.Server.MaxClients
	if maxClients <= 0 {
		maxClients = 64
	}

	s := &Server{
		config:        cfg,
		serverNumeric: p10.ServerNumeric(serverNum),
		numerics:      p10.NewNumericAllocator(serverNum, maxClients),
		network:       network.New(),
		batches:       ircv3.NewBatchTracker(),
		msgHandlers:   make(map[string]MessageHandler),
		pseudoClients: make(map[string]*PseudoClient),
		crypto:        NewS2SCrypto(cfg.Uplink.HMACKey, cfg.Uplink.HMACScheme),
		hooks:         NewHookManager(),
		limiter: NewRateLimiter(
			cfg.Services.Flood.MaxPerSecond,
			cfg.Services.Flood.MaxBurst,
			cfg.Services.Flood.CooldownSecs,
		),
		shutdown:      make(chan struct{}),
		done:          make(chan struct{}),
	}

	// Initialize encrypted data store
	dbCrypto := store.NewCryptoStore(cfg.Server.DBEncryptionKey)
	if dbCrypto.Enabled() {
		log.Println("Database encryption enabled (AES-256-GCM)")
	}

	// Initialize stores
	if cfg.IRCv3.EnableChathistory {
		maxHist := cfg.IRCv3.MaxHistoryPerChannel
		if maxHist <= 0 {
			maxHist = 10000
		}
		s.messages = store.NewMessageStore("data/history", maxHist, dbCrypto)
	}
	s.quotes = store.NewQuoteStore("data/quotes.json", dbCrypto)

	s.registerHandlers()

	return s, nil
}

// Run connects to Cathexis and starts the main loop.
func (s *Server) Run() error {
	// Capture the done channel at function start — if resetForReconnect
	// replaces s.done before our defer fires, we close the right one.
	doneCh := s.done
	defer func() {
		select {
		case <-doneCh:
			// already closed
		default:
			close(doneCh)
		}
	}()

	if err := s.connect(); err != nil {
		return fmt.Errorf("connect: %w", err)
	}
	defer s.conn.Close()

	if err := s.register(); err != nil {
		return fmt.Errorf("register: %w", err)
	}

	// Activate per-message HMAC signing now that link auth is complete
	if s.config.Uplink.HMACKey != "" {
		s.hmacActive = true
		log.Printf("S2S-HMAC: Per-message signing activated")
	}

	if err := s.burst(); err != nil {
		return fmt.Errorf("burst: %w", err)
	}

	log.Printf("Connected to %s, entering main loop", s.config.Uplink.Host)
	s.running = true

	// Start periodic rate limiter cleanup
	go func() {
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-s.shutdown:
				return
			case <-ticker.C:
				s.limiter.Cleanup(10 * time.Minute)
			}
		}
	}()

	return s.readLoop()
}

// Shutdown signals the server to stop.
func (s *Server) Shutdown() {
	select {
	case <-s.shutdown:
		return // already shutting down
	default:
		close(s.shutdown)
	}

	// Shut down modules
	for _, m := range s.modules {
		m.Shutdown()
	}

	// Flush stores
	if s.messages != nil {
		s.messages.Shutdown()
	}

	// Send SQUIT
	if s.conn != nil {
		_ = s.sendRawLine(fmt.Sprintf("%s SQ %s 0 :Shutting down",
			s.serverNumeric, s.config.Server.Name))
	}

	if s.conn != nil {
		s.conn.Close()
	}
}

// connect establishes a TLS connection to Cathexis.
func (s *Server) connect() error {
	addr := fmt.Sprintf("%s:%d", s.config.Uplink.Host, s.config.Uplink.Port)
	log.Printf("Connecting to %s (TLS: %v)", addr, s.config.Uplink.TLS)

	if s.config.Uplink.TLS {
		tlsCfg := &tls.Config{
			MinVersion:         tls.VersionTLS12,
			InsecureSkipVerify: s.config.Uplink.TLSSkipVerify,
		}

		// Load CA cert if configured
		if s.config.Uplink.TLSCA != "" {
			caCert, err := os.ReadFile(s.config.Uplink.TLSCA)
			if err != nil {
				return fmt.Errorf("read CA cert: %w", err)
			}
			pool := x509.NewCertPool()
			if !pool.AppendCertsFromPEM(caCert) {
				return fmt.Errorf("failed to parse CA cert")
			}
			tlsCfg.RootCAs = pool
		}

		// Load client certificate if configured
		if s.config.Uplink.TLSCert != "" && s.config.Uplink.TLSKey != "" {
			cert, err := tls.LoadX509KeyPair(s.config.Uplink.TLSCert, s.config.Uplink.TLSKey)
			if err != nil {
				return fmt.Errorf("load TLS cert: %w", err)
			}
			tlsCfg.Certificates = []tls.Certificate{cert}
		}

		conn, err := tls.DialWithDialer(
			&net.Dialer{Timeout: 30 * time.Second},
			"tcp", addr, tlsCfg,
		)
		if err != nil {
			return fmt.Errorf("TLS dial: %w", err)
		}
		s.conn = conn
	} else {
		conn, err := net.DialTimeout("tcp", addr, 30*time.Second)
		if err != nil {
			return fmt.Errorf("dial: %w", err)
		}
		s.conn = conn
	}

	s.reader = bufio.NewReaderSize(s.conn, 8192)
	s.writer = bufio.NewWriterSize(s.conn, 8192)

	log.Printf("Connected to %s", addr)
	return nil
}

// register performs P10 link registration: PASS, SERVER.
func (s *Server) register() error {
	// PASS
	if err := s.sendRawLine(fmt.Sprintf("PASS :%s", s.config.Uplink.Password)); err != nil {
		return fmt.Errorf("send PASS: %w", err)
	}

	// SERVER
	ts := time.Now().Unix()
	if err := s.sendRawLine(fmt.Sprintf("SERVER %s %d %d %d J10 %s]]] +s6 :%s",
		s.config.Server.Name,
		1, // hop count
		ts,
		ts,
		s.serverNumeric,
		s.config.Server.Description,
	)); err != nil {
		return fmt.Errorf("send SERVER: %w", err)
	}

	log.Printf("Sent registration: %s numeric=%s", s.config.Server.Name, s.serverNumeric)

	// Read until we get SERVER or ERROR back
	for {
		line, err := s.readLine()
		if err != nil {
			return fmt.Errorf("read during registration: %w", err)
		}

		msg := ircv3.ParseP10Line(line)

		switch msg.Command {
		case "SERVER", "S":
			// Remote server introduction — store it
			s.handleServerIntro(msg)
			return nil
		case "PASS", "PA":
			// Ignore PASS echo
			continue
		case "ERROR", "Y":
			return fmt.Errorf("server rejected link: %s", msg.Trailing())
		default:
			if s.config.Debug {
				log.Printf("[REG] unexpected: %s", line)
			}
		}
	}
}

// burst sends our BURST to introduce pseudo-clients.
func (s *Server) burst() error {
	log.Printf("Sending BURST")

	// Read remote server's burst first
	if err := s.readRemoteBurst(); err != nil {
		return fmt.Errorf("read remote burst: %w", err)
	}

	// Send our burst — introduce pseudo-clients, then EB.
	// Modules MUST introduce pseudo-clients during burst phase,
	// before EB, so Cathexis sees them as part of our initial state.
	s.initModules()

	// End of burst
	if err := s.sendRawLine(fmt.Sprintf("%s EB", s.serverNumeric)); err != nil {
		return err
	}

	log.Printf("BURST sent, waiting for EOB_ACK")

	// Wait for remote EOB_ACK
	for {
		line, err := s.readLine()
		if err != nil {
			return fmt.Errorf("read EOB_ACK: %w", err)
		}
		msg := ircv3.ParseP10Line(line)
		s.processMessage(msg)

		if msg.Command == "EA" || msg.Command == "EOB_ACK" {
			break
		}
	}

	// Send our EOB_ACK
	if err := s.sendRawLine(fmt.Sprintf("%s EA", s.serverNumeric)); err != nil {
		return err
	}

	log.Printf("BURST complete, link synchronized")
	s.burstDone = true
	return nil
}

// readRemoteBurst reads the remote server's BURST sequence.
func (s *Server) readRemoteBurst() error {
	for {
		line, err := s.readLine()
		if err != nil {
			return fmt.Errorf("read burst: %w", err)
		}

		msg := ircv3.ParseP10Line(line)
		s.processMessage(msg)

		if msg.Command == "EB" || msg.Command == "END_OF_BURST" {
			log.Printf("Remote BURST complete (%d users, %d channels, %d servers)",
				s.network.UserCount(), s.network.ChannelCount(), s.network.ServerCount())
			break
		}
	}
	return nil
}

// processMessage handles a message during BURST and registration.
// Used before the main readLoop starts.
func (s *Server) processMessage(msg *ircv3.P10Message) {
	switch msg.Command {
	case "S", "SERVER":
		s.handleServerIntro(msg)
	case "N", "NICK":
		s.handleNickIntro(msg)
	case "B", "BURST":
		s.handleBurstChannel(msg)
	case "EB", "END_OF_BURST":
		// handled by caller
	case "EA", "EOB_ACK":
		// handled by caller
	case "G", "PING":
		s.handlePing(msg)
	default:
		s.dispatchMessage(msg)
	}
}

// readLoop is the main message processing loop.
func (s *Server) readLoop() error {
	for {
		select {
		case <-s.shutdown:
			return nil
		default:
		}

		// Set read deadline to detect dead connections
		_ = s.conn.SetReadDeadline(time.Now().Add(5 * time.Minute))

		line, err := s.readLine()
		if err != nil {
			select {
			case <-s.shutdown:
				return nil
			default:
				return fmt.Errorf("read: %w", err)
			}
		}

		msg := ircv3.ParseP10Line(line)
		s.processMainMessage(msg)
	}
}

// processMainMessage handles a message in the main loop.
func (s *Server) processMainMessage(msg *ircv3.P10Message) {
	switch msg.Command {
	case "G", "PING":
		s.handlePing(msg)
	case "S", "SERVER":
		s.handleServerIntro(msg)
	case "SQ", "SQUIT":
		s.handleSquit(msg)
	case "N", "NICK":
		s.handleNickMessage(msg)
	case "Q", "QUIT":
		s.handleQuitMessage(msg)
	case "J", "JOIN":
		s.handleJoinMessage(msg)
	case "C", "CREATE":
		s.handleCreateMessage(msg)
	case "L", "PART":
		s.handlePartMessage(msg)
	case "K", "KICK":
		s.handleKickMessage(msg)
	case "M", "MODE":
		s.handleModeMessage(msg)
	case "T", "TOPIC":
		s.handleTopicMessage(msg)
	case "AC", "ACCOUNT":
		s.handleAccountMessage(msg)
	case "A", "AWAY":
		s.handleAwayMessage(msg)
	case "D", "KILL":
		s.handleKillMessage(msg)
	case "P", "PRIVMSG":
		s.handlePrivmsgMessage(msg)
	case "O", "NOTICE":
		s.handleNoticeMessage(msg)
	case "XQ", "XQUERY":
		s.handleXQuery(msg)
	case "BA", "BATCH":
		s.handleBatchTracking(msg)
	case "B", "BURST":
		s.handleBurstChannel(msg)
	case "W", "WHOIS":
		s.handleWhoisMessage(msg)
	case "Y", "ERROR":
		log.Printf("[ERROR] from server: %s", msg.Trailing())
	// P10 commands that don't need processing by services
	case "MK", "MARK":
		// Server metadata markers. Broadcast to modules so Sentinel can
		// score DNSBL marks emitted by Cathexis 1.5.6+. Modules that don't
		// care return early; Sentinel parses the zone list in the mark
		// and applies weighted scoring.
		for _, m := range s.modules {
			m.HandleMessage(s, msg)
		}
	case "PRIVS":          // oper privilege display
	case "SNO":            // server notice routing
	case "OM", "OPMODE":   // oper mode changes (already handled by M/MODE)
	case "Z", "PONG":      // pong echo response
	case "DS", "DESTRUCT": // empty channel destruct
	case "RI", "RPING":    // remote ping
	case "RO", "RPONG":    // remote pong
	case "SE", "SETTIME":  // time sync
	case "WC", "WALLCHOPS":// channel wallops
	case "WU", "WALLUSERS":// network-wide notice
	case "WA", "WALLOPS":  // oper wallops
	default:
		if s.config.Debug {
			log.Printf("[UNHANDLED] %s from %s", msg.Command, msg.Source)
		}
	}
}

// --- P10 message handlers ---

func (s *Server) handleServerIntro(msg *ircv3.P10Message) {
	// SERVER format: <name> <hopcount> <start_ts> <link_ts> <protocol> <numeric+maxconn> <flags> :<description>
	if len(msg.Params) < 7 {
		return
	}
	name := msg.Param(0)
	// numeric+maxconn follows "J10" at Param(4), so it is Param(5)
	numericAndMax := msg.Param(5)
	if msg.Param(4) != "J10" {
		// Fallback if protocol field is missing or shifted
		numericAndMax = msg.Param(4)
	}

	// Extract server numeric (first 2 chars of the numeric+maxconn field)
	srvNumeric := ""
	if len(numericAndMax) >= 2 {
		srvNumeric = numericAndMax[:2]
	}

	s.network.AddServer(&network.Server{
		Numeric:     srvNumeric,
		Name:        name,
		Description: msg.Trailing(),
		LinkTime:    time.Now(),
		Uplink:      msg.Source,
	})

	if s.config.Debug {
		log.Printf("[SERVER] %s (%s) linked", name, srvNumeric)
	}
}

func (s *Server) handleNickIntro(msg *ircv3.P10Message) {
	// P10 NICK during BURST:
	// <server> N <nick> <hop> <ts> <ident> <host> <modes> [<mode-params>...] <ip-b64> <numeric> :<gecos>
	// The IP is base64-encoded, numeric is always the last non-trailing param.
	if len(msg.Params) < 7 {
		return
	}

	nick := msg.Param(0)
	ident := msg.Param(3)
	host := msg.Param(4)
	modes := msg.Param(5)

	// In P10, numeric is always the last non-trailing param.
	// IP (base64) is second-to-last non-trailing.
	// Trailing (gecos) is already separated by the parser.
	// Find numeric by scanning from the end for a 5-char base64 string.
	numeric := ""
	ip := ""
	for i := len(msg.Params) - 1; i >= 6; i-- {
		if p10.IsUserNumeric(msg.Params[i]) {
			numeric = msg.Params[i]
			if i > 6 {
				ip = msg.Params[i-1]
			}
			break
		}
	}

	// Extract account from mode params if +r is set
	account := ""
	if strings.Contains(modes, "r") {
		// Account name follows the mode string as a mode parameter
		// Format: account:timestamp
		for i := 6; i < len(msg.Params); i++ {
			p := msg.Params[i]
			if p != ip && !p10.IsUserNumeric(p) && !strings.HasPrefix(p, "+") {
				// Strip :timestamp if present
				if idx := strings.IndexByte(p, ':'); idx >= 0 {
					account = p[:idx]
				} else {
					account = p
				}
				break
			}
		}
	}

	// Also check tags for account
	if account == "" {
		if acct, ok := msg.GetTag("account"); ok {
			account = acct
		}
	}

	gecos := msg.Trailing()
	serverPart, _ := p10.ParseUserNumeric(numeric)

	s.network.AddUser(&network.User{
		Numeric:   numeric,
		Nick:      nick,
		Ident:     ident,
		Host:      host,
		IP:        ip,
		Gecos:     gecos,
		Modes:     modes,
		Server:    serverPart,
		Account:   account,
		Timestamp: time.Now(),
	})
}

func (s *Server) handleNickMessage(msg *ircv3.P10Message) {
	if p10.IsUserNumeric(msg.Source) {
		// Nick change: <numeric> N <newnick> <ts>
		if len(msg.Params) >= 1 {
			newNick := msg.Param(0)
			s.network.ChangeNick(msg.Source, newNick, time.Now())
			s.hooks.Fire(EventNick, s, msg)
		}
	} else {
		// New user intro (during normal operation, not BURST)
		s.handleNickIntro(msg)
	}
}

func (s *Server) handleBurstChannel(msg *ircv3.P10Message) {
	// B <channel> <ts> [+modes [params]] [<member-list>] [:%bans]
	if len(msg.Params) < 2 {
		return
	}

	chName := msg.Param(0)
	ch := &network.Channel{
		Name:    chName,
		Members: make(map[string]string),
	}

	// Parse remaining params for modes and members
	for i := 2; i < len(msg.Params); i++ {
		param := msg.Params[i]
		if strings.HasPrefix(param, "+") {
			ch.Modes = param
		} else if strings.HasPrefix(param, "%") {
			// Ban list (in trailing param: %ban1 ban2 ban3)
			banStr := param[1:]
			if banStr != "" {
				ch.Bans = append(ch.Bans, strings.Fields(banStr)...)
			}
		} else if strings.Contains(param, ",") || p10.IsUserNumeric(param) || (len(param) >= 5 && strings.Contains(param, ":")) {
			// Member list: ABAAB,ABAAC:o,ABAAD:v
			members := strings.Split(param, ",")
			for _, m := range members {
				parts := strings.SplitN(m, ":", 2)
				numeric := parts[0]
				modes := ""
				if len(parts) > 1 {
					modes = parts[1]
				}
				if p10.IsUserNumeric(numeric) {
					ch.Members[numeric] = modes
					// Update user's channel list
					if u := s.network.GetUser(numeric); u != nil {
						s.network.JoinChannel(numeric, chName, modes)
					}
				}
			}
		}
	}

	s.network.AddChannel(ch)
}

func (s *Server) handleJoinMessage(msg *ircv3.P10Message) {
	// <numeric> J <channel> [<ts>]
	if len(msg.Params) < 1 {
		return
	}
	channels := strings.Split(msg.Param(0), ",")
	for _, ch := range channels {
		if ch == "0" {
			// Part all channels
			continue
		}
		s.network.JoinChannel(msg.Source, ch, "")
	}
	s.hooks.Fire(EventJoin, s, msg)
}

func (s *Server) handleCreateMessage(msg *ircv3.P10Message) {
	// <numeric> C <channel> <ts>
	if len(msg.Params) < 1 {
		return
	}
	s.network.JoinChannel(msg.Source, msg.Param(0), "o")
	s.hooks.Fire(EventJoin, s, msg)
}

func (s *Server) handlePartMessage(msg *ircv3.P10Message) {
	if len(msg.Params) < 1 {
		return
	}
	channels := strings.Split(msg.Param(0), ",")
	for _, ch := range channels {
		s.network.PartChannel(msg.Source, ch)
	}
	s.hooks.Fire(EventPart, s, msg)
}

func (s *Server) handleQuitMessage(msg *ircv3.P10Message) {
	s.hooks.Fire(EventQuit, s, msg)
	s.network.RemoveUser(msg.Source)
	s.limiter.Reset(msg.Source)
}

func (s *Server) handleKickMessage(msg *ircv3.P10Message) {
	// <source> K <channel> <target> :<reason>
	if len(msg.Params) < 2 {
		return
	}
	s.network.PartChannel(msg.Param(1), msg.Param(0))
	s.hooks.Fire(EventKick, s, msg)
}

func (s *Server) handleModeMessage(msg *ircv3.P10Message) {
	if len(msg.Params) < 2 {
		return
	}
	target := msg.Param(0)
	modes := msg.Param(1)

	if strings.HasPrefix(target, "#") || strings.HasPrefix(target, "&") ||
		strings.HasPrefix(target, "+") || strings.HasPrefix(target, "!") {
		s.network.SetChannelModes(target, modes)
	} else if p10.IsUserNumeric(target) {
		s.network.SetUserModes(target, modes)
	}
	s.hooks.Fire(EventMode, s, msg)
}

func (s *Server) handleTopicMessage(msg *ircv3.P10Message) {
	if len(msg.Params) < 1 {
		return
	}
	channel := msg.Param(0)
	topic := msg.Trailing()

	sourceNick := msg.Source
	if u := s.network.GetUser(msg.Source); u != nil {
		sourceNick = u.Nick
	}

	s.network.SetChannelTopic(channel, topic, sourceNick, time.Now())
	s.hooks.Fire(EventTopic, s, msg)
}

func (s *Server) handleAccountMessage(msg *ircv3.P10Message) {
	// P10 ACCOUNT format:
	//   <server> AC <target_numeric> R <account> <timestamp>   — authenticated
	//   <server> AC <target_numeric> M <account> <timestamp>   — admin auth
	//   <server> AC <target_numeric>                           — logout
	if len(msg.Params) < 1 {
		return
	}
	target := msg.Param(0)

	account := ""
	if len(msg.Params) >= 3 {
		// R/M <account> <ts>
		account = msg.Param(2)
		// Handle account:timestamp format
		if idx := strings.IndexByte(account, ':'); idx >= 0 {
			account = account[:idx]
		}
	}

	s.network.SetUserAccount(target, account)
	s.hooks.Fire(EventAccount, s, msg)
}

func (s *Server) handleAwayMessage(msg *ircv3.P10Message) {
	away := msg.Trailing()
	s.network.SetUserAway(msg.Source, away)
	s.hooks.Fire(EventAway, s, msg)
}

func (s *Server) handleKillMessage(msg *ircv3.P10Message) {
	// <source> D <target> :<reason>
	if len(msg.Params) < 1 {
		return
	}
	target := msg.Param(0)

	// Check if one of our pseudo-clients was killed
	s.pseudoMu.RLock()
	pc, isPseudo := s.pseudoClients[target]
	s.pseudoMu.RUnlock()

	if isPseudo {
		log.Printf("[KILL] Pseudo-client %s (%s) killed by %s: %s",
			pc.Nick, target, msg.Source, msg.Trailing())
		// Re-introduce the pseudo-client
		go func() {
			time.Sleep(2 * time.Second)
			s.reintroducePseudoClient(pc)
		}()
	}

	s.network.RemoveUser(target)
}

func (s *Server) handleSquit(msg *ircv3.P10Message) {
	// <source> SQ <servername> <ts> :<reason>
	if len(msg.Params) < 1 {
		return
	}
	serverName := msg.Param(0)
	log.Printf("[SQUIT] Server %s delinked: %s", serverName, msg.Trailing())

	// Find server numeric by name and cascade-remove all its users
	for _, srv := range []string{msg.Param(0)} {
		_ = srv
	}
	// Walk servers to find by name
	// network.RemoveServer handles cascading user removal
	if srvState := s.network.GetServer(msg.Source); srvState != nil {
		s.network.RemoveServer(srvState.Numeric)
	}
}

func (s *Server) handlePing(msg *ircv3.P10Message) {
	// Respond with PONG
	target := msg.Trailing()
	if target == "" && len(msg.Params) > 0 {
		target = msg.Param(0)
	}
	_ = s.sendRawLine(fmt.Sprintf("%s Z %s :%s",
		s.serverNumeric, msg.Source, s.config.Server.Name))
}

func (s *Server) handlePrivmsgMessage(msg *ircv3.P10Message) {
	if len(msg.Params) < 2 {
		return
	}

	target := msg.Param(0)
	text := msg.Trailing()

	// Record message in history store
	if s.messages != nil {
		sourceNick := msg.Source
		sourceAccount := ""
		if u := s.network.GetUser(msg.Source); u != nil {
			sourceNick = fmt.Sprintf("%s!%s@%s", u.Nick, u.Ident, u.Host)
			sourceAccount = u.Account
		}
		msgID, _ := msg.GetTag("msgid")
		if msgID == "" {
			msgID = ircv3.GenerateMsgID()
		}
		s.messages.Add(store.StoredMessage{
			MsgID:   msgID,
			Time:    serverTimeFromTags(msg.Tags),
			Source:  sourceNick,
			Account: sourceAccount,
			Target:  target,
			Command: "PRIVMSG",
			Text:    text,
		})
	}

	// Fire EventMessage hook for channel messages (stats/logging)
	if isChannelName(target) {
		s.hooks.Fire(EventMessage, s, msg)
	}

	// Check if this is directed at one of our pseudo-clients
	s.pseudoMu.RLock()
	pc, isPseudo := s.pseudoClients[target]
	if !isPseudo {
		// Fallback: try nick@server format (directed messages)
		nickPart := target
		if at := strings.IndexByte(target, '@'); at > 0 {
			nickPart = target[:at]
		}
		for _, candidate := range s.pseudoClients {
			if strings.EqualFold(candidate.Nick, nickPart) ||
				strings.EqualFold(candidate.Nick, target) {
				pc = candidate
				isPseudo = true
				break
			}
		}
	}
	s.pseudoMu.RUnlock()

	if isPseudo && pc.Module != nil {
		// Rate limit service commands
		if !s.limiter.Allow(msg.Source) {
			s.SendNotice(pc.Numeric, msg.Source, "You are sending commands too fast. Please wait.")
			return
		}
		// Check CTCP first
		if len(text) > 0 && text[0] == '\x01' {
			for _, m := range s.modules {
				if m.Name() == "ctcp" {
					m.HandleMessage(s, msg)
					return
				}
			}
		}

		// Bot request system: allow channel owners to JOIN/PART bots
		if s.handleBotRequest(pc, msg, text) {
			return
		}

		pc.Module.HandleMessage(s, msg)
		return
	}

	// Check if it's a channel message with our prefix
	if isChannelName(target) && strings.HasPrefix(text, s.config.Services.Prefix) {
		// Rate limit
		if !s.limiter.Allow(msg.Source) {
			return
		}
		// Dispatch to modules
		for _, m := range s.modules {
			m.HandleMessage(s, msg)
		}
	}
}

func (s *Server) handleNoticeMessage(msg *ircv3.P10Message) {
	// Record NOTICEs in history store (but don't respond to avoid loops)
	if s.messages != nil && len(msg.Params) >= 2 {
		sourceNick := msg.Source
		sourceAccount := ""
		if u := s.network.GetUser(msg.Source); u != nil {
			sourceNick = fmt.Sprintf("%s!%s@%s", u.Nick, u.Ident, u.Host)
			sourceAccount = u.Account
		}
		msgID, _ := msg.GetTag("msgid")
		if msgID == "" {
			msgID = ircv3.GenerateMsgID()
		}
		s.messages.Add(store.StoredMessage{
			MsgID:   msgID,
			Time:    serverTimeFromTags(msg.Tags),
			Source:  sourceNick,
			Account: sourceAccount,
			Target:  msg.Param(0),
			Command: "NOTICE",
			Text:    msg.Trailing(),
		})
	}
	if s.config.Debug {
		log.Printf("[NOTICE] %s -> %s: %s", msg.Source, msg.Param(0), msg.Trailing())
	}
}

func (s *Server) handleWhoisMessage(msg *ircv3.P10Message) {
	// P10 WHOIS: <source> W <target-server> :<nick>
	if len(msg.Params) < 1 {
		return
	}
	nick := msg.Trailing()
	if nick == "" {
		nick = msg.Param(0)
	}

	// Find the user
	u := s.network.FindUserByNick(nick)
	if u == nil {
		// 401 ERR_NOSUCHNICK
		_ = s.sendRawLine(fmt.Sprintf("%s 401 %s %s :No such nick",
			s.serverNumeric, msg.Source, nick))
		_ = s.sendRawLine(fmt.Sprintf("%s 318 %s %s :End of /WHOIS list",
			s.serverNumeric, msg.Source, nick))
		return
	}

	// Check if it is one of our pseudo-clients for detailed response
	s.pseudoMu.RLock()
	_, isPseudo := s.pseudoClients[u.Numeric]
	s.pseudoMu.RUnlock()

	if isPseudo {
		// 311 RPL_WHOISUSER
		_ = s.sendRawLine(fmt.Sprintf("%s 311 %s %s %s %s * :%s",
			s.serverNumeric, msg.Source, u.Nick, u.Ident, u.Host, u.Gecos))
		// 312 RPL_WHOISSERVER
		_ = s.sendRawLine(fmt.Sprintf("%s 312 %s %s %s :%s",
			s.serverNumeric, msg.Source, u.Nick, s.config.Server.Name, s.config.Server.Description))
		// 313 RPL_WHOISOPERATOR
		_ = s.sendRawLine(fmt.Sprintf("%s 313 %s %s :is a Network Service",
			s.serverNumeric, msg.Source, u.Nick))
		// 330 RPL_WHOISACCOUNT (if logged in)
		if u.Account != "" {
			_ = s.sendRawLine(fmt.Sprintf("%s 330 %s %s %s :is logged in as",
				s.serverNumeric, msg.Source, u.Nick, u.Account))
		}
		// 318 RPL_ENDOFWHOIS
		_ = s.sendRawLine(fmt.Sprintf("%s 318 %s %s :End of /WHOIS list",
			s.serverNumeric, msg.Source, u.Nick))
	}
}

// --- Pseudo-client management ---

// IntroducePseudoClient sends a P10 N line to introduce a pseudo-client.
// Includes +B (bot mode) per IRCv3 bot-mode spec.
func (s *Server) IntroducePseudoClient(nick, ident, host, gecos string, mod Module) (*PseudoClient, error) {
	numeric, err := s.numerics.Allocate()
	if err != nil {
		return nil, fmt.Errorf("allocate numeric: %w", err)
	}

	// Build modes — always include +B for bot-mode
	modes := ircv3.BuildNickModes("")

	ts := time.Now().Unix()

	// P10 NICK intro: <server> N <nick> <hopcount> <ts> <ident> <host> <modes> <ip> <numeric> :<gecos>
	err = s.sendRawLine(fmt.Sprintf("%s N %s 1 %d %s %s %s AAAAAA %s :%s",
		s.serverNumeric, nick, ts, ident, host, modes, numeric, gecos))
	if err != nil {
		s.numerics.Release(numeric)
		return nil, fmt.Errorf("send NICK: %w", err)
	}

	pc := &PseudoClient{
		Numeric: numeric,
		Nick:    nick,
		Ident:   ident,
		Host:    host,
		Gecos:   gecos,
		Modes:   modes,
		Module:  mod,
	}

	s.pseudoMu.Lock()
	s.pseudoClients[numeric] = pc
	s.pseudoMu.Unlock()

	// Add to network state
	s.network.AddUser(&network.User{
		Numeric:   numeric,
		Nick:      nick,
		Ident:     ident,
		Host:      host,
		Gecos:     gecos,
		Modes:     modes,
		Server:    s.serverNumeric,
		Timestamp: time.Now(),
		Account:   nick, // Pseudo-clients use their nick as account
	})

	log.Printf("[PSEUDO] Introduced %s (%s) with modes %s", nick, numeric, modes)
	return pc, nil
}

// reintroducePseudoClient re-introduces a killed pseudo-client.
func (s *Server) reintroducePseudoClient(pc *PseudoClient) {
	newPC, err := s.IntroducePseudoClient(pc.Nick, pc.Ident, pc.Host, pc.Gecos, pc.Module)
	if err != nil {
		log.Printf("[PSEUDO] Failed to reintroduce %s: %v", pc.Nick, err)
		return
	}

	// Remove old numeric, add new
	s.pseudoMu.Lock()
	delete(s.pseudoClients, pc.Numeric)
	s.pseudoClients[newPC.Numeric] = newPC
	s.pseudoMu.Unlock()

	log.Printf("[PSEUDO] Reintroduced %s as %s", pc.Nick, newPC.Numeric)
}

// JoinPseudoClient makes a pseudo-client join a channel.
func (s *Server) JoinPseudoClient(numeric, channel string) error {
	ts := time.Now().Unix()
	err := s.sendRawLine(fmt.Sprintf("%s J %s %d", numeric, channel, ts))
	if err != nil {
		return err
	}
	s.network.JoinChannel(numeric, channel, "")
	return nil
}

// PartPseudoClient parts a pseudo-client from a channel.
func (s *Server) PartPseudoClient(numeric, channel string) error {
	err := s.sendRawLine(fmt.Sprintf("%s L %s", numeric, channel))
	if err != nil {
		return err
	}
	s.network.PartChannel(numeric, channel)
	return nil
}

// requestableBots lists bot module names that channel owners can request.
// Bots NOT in this list (RootServ, DroneScan, Trap, V) require admin.
var requestableBots = map[string]bool{
	"funserv":  true,
	"moo":       true,
	"limitserv": true,
	"statserv":  true,
}

// handleBotRequest checks if a DM to a pseudo-client is a JOIN/PART request
// from a channel owner. Returns true if handled.
func (s *Server) handleBotRequest(pc *PseudoClient, msg *ircv3.P10Message, text string) bool {
	fields := strings.Fields(text)
	if len(fields) < 1 {
		return false
	}

	cmd := strings.ToUpper(fields[0])
	if cmd != "JOIN" && cmd != "PART" && cmd != "REQUEST" && cmd != "RELEASE" && cmd != "HELP" {
		return false
	}

	// Handle HELP for requestable bots — show request commands, then let module add its own
	if cmd == "HELP" && pc.Module != nil && requestableBots[strings.ToLower(pc.Module.Name())] {
		_ = s.SendNotice(pc.Numeric, msg.Source, fmt.Sprintf("--- %s ---", pc.Nick))
		_ = s.SendNotice(pc.Numeric, msg.Source, fmt.Sprintf("  JOIN <#channel>    — Request %s to join your channel", pc.Nick))
		_ = s.SendNotice(pc.Numeric, msg.Source, fmt.Sprintf("  PART <#channel>    — Remove %s from your channel", pc.Nick))
		_ = s.SendNotice(pc.Numeric, msg.Source, "  Requires channel operator access.")
		return false // let module also show its own commands
	}

	if len(fields) < 2 {
		return false
	}

	channel := fields[1]
	if !isChannelName(channel) {
		_ = s.SendNotice(pc.Numeric, msg.Source, fmt.Sprintf("Invalid channel name: %s", channel))
		return true
	}

	// Check if this bot is requestable by users
	moduleName := ""
	if pc.Module != nil {
		moduleName = strings.ToLower(pc.Module.Name())
	}

	u := s.network.GetUser(msg.Source)
	if u == nil {
		_ = s.SendNotice(pc.Numeric, msg.Source, "Unable to verify your identity.")
		return true
	}

	if !requestableBots[moduleName] {
		// Non-requestable bot — require admin
		if !s.CheckPrivilege(msg.Source, PrivAdmin) {
			_ = s.SendNotice(pc.Numeric, msg.Source,
				fmt.Sprintf("%s is not available for channel requests. Contact an administrator.", pc.Nick))
			return true
		}
	} else {
		// Requestable bot — require channel owner/op or admin
		if !s.CheckPrivilege(msg.Source, PrivAdmin) {
			// Check channel access: must have +o or +q in the target channel
			chanModes, inChannel := u.Channels[channel]
			if !inChannel || (!strings.Contains(chanModes, "o") && !strings.Contains(chanModes, "q")) {
				_ = s.SendNotice(pc.Numeric, msg.Source,
					fmt.Sprintf("You must be a channel operator in %s to request %s.", channel, pc.Nick))
				return true
			}
		}
	}

	switch cmd {
	case "JOIN", "REQUEST":
		_ = s.JoinPseudoClient(pc.Numeric, channel)
		_ = s.SendNotice(pc.Numeric, msg.Source,
			fmt.Sprintf("%s has joined %s.", pc.Nick, channel))
		log.Printf("[BOTREQ] %s (%s) requested %s JOIN %s", u.Nick, u.Account, pc.Nick, channel)
		// Fire join hook so modules (e.g. StatServ) can react to their own join
		s.hooks.Fire(EventJoin, s, &ircv3.P10Message{
			Source:  pc.Numeric,
			Command: "J",
			Params:  []string{channel},
		})
	case "PART", "RELEASE":
		_ = s.PartPseudoClient(pc.Numeric, channel)
		_ = s.SendNotice(pc.Numeric, msg.Source,
			fmt.Sprintf("%s has left %s.", pc.Nick, channel))
		log.Printf("[BOTREQ] %s (%s) requested %s PART %s", u.Nick, u.Account, pc.Nick, channel)
		// Fire part hook
		s.hooks.Fire(EventPart, s, &ircv3.P10Message{
			Source:  pc.Numeric,
			Command: "L",
			Params:  []string{channel},
		})
	}

	return true
}

// --- I/O ---

// readLine reads a single \r\n-terminated line from the connection.
func (s *Server) readLine() (string, error) {
	line, err := s.reader.ReadString('\n')
	if err != nil {
		return "", err
	}
	line = strings.TrimRight(line, "\r\n")
	if s.config.Debug {
		log.Printf("[RECV] %s", line)
	}
	return line, nil
}

// sendRawLine sends a raw line to the connection (with \r\n).
// When S2S HMAC is active, prepends @hmac=<signature> tag.
// Any existing IRCv3 tags in the line are STRIPPED before signing
// and sending — S2S P10 must be bare protocol.
func (s *Server) sendRawLine(line string) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()

	// Strip any IRCv3 tag prefix (@key=value;... ) before signing.
	// S2S P10 does not support tags — the ircd will reject them.
	bareLine := line
	if len(line) > 0 && line[0] == '@' {
		if sp := strings.IndexByte(line, ' '); sp > 0 {
			bareLine = line[sp+1:]
		}
	}

	outLine := bareLine
	if s.hmacActive && len(s.crypto.key) > 0 {
		sig := s.crypto.SignMessage(bareLine)
		outLine = "@hmac=" + sig + " " + bareLine
	}

	if s.config.Debug {
		log.Printf("[SEND] %s", outLine)
	}

	_, err := fmt.Fprintf(s.writer, "%s\r\n", outLine)
	if err != nil {
		return err
	}
	return s.writer.Flush()
}

// registerHandlers sets up the IRCv3-aware command handler map.
func (s *Server) registerHandlers() {
	// All handlers are in processMainMessage via switch.
	// msgHandlers map is used by dispatch.go for module routing.
}

// initModules initializes all registered service modules.
func (s *Server) initModules() {
	for _, m := range s.modules {
		if err := m.Init(s); err != nil {
			log.Printf("[MODULE] Failed to init %s: %v", m.Name(), err)
			continue
		}
		// Register event hooks if module supports them
		if hm, ok := m.(HookableModule); ok {
			hm.RegisterHooks(s.hooks)
		}
	}
	log.Printf("Module initialization complete (%d modules)", len(s.modules))
}

// RegisterModule adds a module to the server.
func (s *Server) RegisterModule(m Module) {
	s.modules = append(s.modules, m)
}

// Modules returns all registered modules.
func (s *Server) Modules() []Module {
	return s.modules
}

// PseudoClients returns a snapshot of all pseudo-client numerics and nicks.
func (s *Server) PseudoClients() map[string]*PseudoClient {
	s.pseudoMu.RLock()
	defer s.pseudoMu.RUnlock()
	out := make(map[string]*PseudoClient, len(s.pseudoClients))
	for k, v := range s.pseudoClients {
		out[k] = v
	}
	return out
}

// FindPseudoByNick looks up a pseudo-client by IRC nick (case-insensitive).
func (s *Server) FindPseudoByNick(nick string) *PseudoClient {
	s.pseudoMu.RLock()
	defer s.pseudoMu.RUnlock()
	lower := strings.ToLower(nick)
	for _, pc := range s.pseudoClients {
		if strings.ToLower(pc.Nick) == lower {
			return pc
		}
	}
	return nil
}

// Network returns the network state (for use by modules).
// BurstDone returns true after the initial S2S burst is complete.
func (s *Server) BurstDone() bool { return s.burstDone }

// Network returns the network state (for use by modules).
func (s *Server) Network() *network.State {
	return s.network
}

// ServerNumeric returns Acid's P10 server numeric string.
func (s *Server) ServerNumeric() string {
	return s.serverNumeric
}

// Config returns the server configuration (for use by modules).
func (s *Server) Config() *config.Config {
	return s.config
}

// Messages returns the message store (for chathistory).
func (s *Server) Messages() *store.MessageStore {
	return s.messages
}

// Quotes returns the quote store.
func (s *Server) Quotes() *store.QuoteStore {
	return s.quotes
}

// Hooks returns the event hook manager.
func (s *Server) Hooks() *HookManager {
	return s.hooks
}

// --- Helpers ---

func isChannelName(s string) bool {
	if len(s) == 0 {
		return false
	}
	return s[0] == '#' || s[0] == '&' || s[0] == '+' || s[0] == '!'
}
