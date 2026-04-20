// Copyright (c) Cathexis Development
// SPDX-License-Identifier: GPL-2.0-only
//
// modules/sentinel.go — Abuse pattern detection with DNSBL integration.
//
// Sentinel monitors IRC traffic for abuse patterns and automatically
// submits offending IPs to a Cerberus DNSBL instance via its HTTP API.
//
// Tracked patterns:
//   - Connection flooding: rapid connects from the same IP
//   - Auth failures: repeated failed NickServ/SASL authentication
//   - Clone flooding: excessive concurrent connections per host
//   - Nick cycling: rapid nick changes (bot signature)
//   - Message flooding: high message rate from a single source
//   - Channel spam: identical messages sent to multiple targets
//   - Join flooding: rapid channel joins across the network
//
// Each pattern has a configurable threshold, time window, score weight,
// and DNSBL category. When an IP accumulates enough score within its
// decay window, Sentinel submits it to Cerberus and optionally sets
// a network G-line.

package modules

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/brandontroidl/noesis/config"
	"github.com/brandontroidl/noesis/ircv3"
	"github.com/brandontroidl/noesis/server"
)

// ── Internal types ─────────────────────────────────────────────────

type ipRecord struct {
	score      int
	lastUpdate time.Time
	listed     bool
	events     map[string][]time.Time // event type -> timestamps
	msgHashes  map[string]int         // message hash -> count (for spam detection)
}

type Sentinel struct {
	pc            *server.PseudoClient
	alertChannel  string
	cerberusURL   string
	cerberusKey   string
	listThreshold int
	decayWindow   time.Duration
	autoGline     bool
	glineDuration int
	glineReason   string
	ttlHours      int
	rules         []config.SentinelRule
	exemptIPs     map[string]bool
	mu            sync.Mutex
	records       map[string]*ipRecord  // IP -> record
	hostToIP      map[string]string     // host -> IP (for correlating events)
	httpClient    *http.Client
	stats         sentinelStats
	stopCh        chan struct{}

	// DNSBL weighted-scoring layer (parses Cathexis 1.5.6+ MARKs).
	dnsblEnabled        bool
	dnsblWarnThreshold  int
	dnsblGlineThreshold int
	dnsblGlineDuration  int
	dnsblGlineReason    string
	dnsblMarkPrefix     string
	dnsblAlertChannel   string
	dnsblZoneWeights    map[string]int    // zone (lowercased) -> weight
	dnsblZoneDescs      map[string]string // zone -> description
}

type sentinelStats struct {
	eventsProcessed int64
	rulesTriggered  int64
	ipsListed       int64
	glinesIssued    int64
}

// Default rules if none are configured.
var defaultRules = []config.SentinelRule{
	{Name: "conn_flood",  Event: "connect",   Threshold: 10, WindowSecs: 60,  Score: 30, Category: 4},
	{Name: "auth_fail",   Event: "auth_fail", Threshold: 5,  WindowSecs: 300, Score: 40, Category: 4},
	{Name: "nick_cycle",  Event: "nick",      Threshold: 8,  WindowSecs: 30,  Score: 25, Category: 3},
	{Name: "msg_flood",   Event: "message",   Threshold: 30, WindowSecs: 10,  Score: 35, Category: 7},
	{Name: "join_flood",  Event: "join",       Threshold: 15, WindowSecs: 10,  Score: 30, Category: 3},
	{Name: "spam",        Event: "spam",       Threshold: 3,  WindowSecs: 60,  Score: 50, Category: 7},
	{Name: "clone_flood", Event: "clone",      Threshold: 5,  WindowSecs: 120, Score: 40, Category: 3},
}

// ── Module interface ───────────────────────────────────────────────

func NewSentinel() *Sentinel {
	return &Sentinel{
		records:    make(map[string]*ipRecord),
		hostToIP:   make(map[string]string),
		exemptIPs:  make(map[string]bool),
		httpClient: &http.Client{Timeout: 10 * time.Second},
		stopCh:     make(chan struct{}),
	}
}

func (s *Sentinel) Name() string  { return "sentinel" }

func (s *Sentinel) Init(srv *server.Server) error {
	cfg := srv.Config().Modules.Sentinel
	if !cfg.Enabled {
		log.Printf("[%s] disabled", s.Name())
		return nil
	}

	s.alertChannel = cfg.AlertChannel
	s.cerberusURL = strings.TrimRight(cfg.CerberusURL, "/")
	s.cerberusKey = cfg.CerberusKey
	s.listThreshold = cfg.ListThreshold
	if s.listThreshold <= 0 { s.listThreshold = 75 }
	s.decayWindow = time.Duration(cfg.DecaySecs) * time.Second
	if s.decayWindow <= 0 { s.decayWindow = 600 * time.Second }
	s.autoGline = cfg.AutoGline
	s.glineDuration = cfg.GlineDuration
	if s.glineDuration <= 0 { s.glineDuration = 3600 }
	s.glineReason = cfg.GlineReason
	if s.glineReason == "" { s.glineReason = "Automated abuse detection" }
	s.ttlHours = cfg.TTLHours
	if s.ttlHours <= 0 { s.ttlHours = 720 }
	s.rules = cfg.Rules
	if len(s.rules) == 0 { s.rules = defaultRules }
	for _, ip := range cfg.ExemptIPs { s.exemptIPs[ip] = true }

	// DNSBL weighted-scoring layer — reads Cathexis 1.5.6+ extended marks.
	ds := cfg.DNSBLScoring
	s.dnsblEnabled = ds.Enabled
	s.dnsblZoneWeights = make(map[string]int)
	s.dnsblZoneDescs = make(map[string]string)
	if s.dnsblEnabled {
		s.dnsblWarnThreshold = ds.WarnThreshold
		if s.dnsblWarnThreshold <= 0 { s.dnsblWarnThreshold = 3 }
		s.dnsblGlineThreshold = ds.GlineThreshold
		if s.dnsblGlineThreshold <= 0 { s.dnsblGlineThreshold = 7 }
		s.dnsblGlineDuration = ds.GlineDuration
		if s.dnsblGlineDuration <= 0 { s.dnsblGlineDuration = 3600 }
		s.dnsblGlineReason = ds.GlineReason
		if s.dnsblGlineReason == "" {
			s.dnsblGlineReason = "DNSBL score exceeded (listed in multiple zones)"
		}
		s.dnsblMarkPrefix = ds.MarkPrefix
		if s.dnsblMarkPrefix == "" { s.dnsblMarkPrefix = "DNSBL" }
		s.dnsblAlertChannel = ds.AlertChannel
		if s.dnsblAlertChannel == "" { s.dnsblAlertChannel = s.alertChannel }
		for _, z := range ds.Zones {
			key := strings.ToLower(z.Zone)
			s.dnsblZoneWeights[key] = z.Weight
			s.dnsblZoneDescs[key] = z.Description
		}
	}

	nick := cfg.Nick
	if nick == "" { nick = "Sentinel" }
	ident := cfg.Ident
	if ident == "" { ident = "sentinel" }
	gecos := cfg.Gecos
	if gecos == "" { gecos = "Network Abuse Detection" }

	pc, err := srv.IntroducePseudoClient(nick, ident, srv.Config().Server.Name, gecos, s)
	if err != nil {
		return fmt.Errorf("introduce %s: %w", nick, err)
	}
	s.pc = pc

	if s.alertChannel != "" {
		_ = srv.JoinPseudoClient(pc.Numeric, s.alertChannel)
	}

	// Background: decay old records every 5 minutes
	go s.decayLoop()

	log.Printf("[%s] initialized as %s — threshold=%d decay=%ds rules=%d cerberus=%s",
		s.Name(), nick, s.listThreshold, int(s.decayWindow.Seconds()),
		len(s.rules), s.cerberusURL)
	return nil
}

// ── Event hooks ────────────────────────────────────────────────────

func (s *Sentinel) RegisterHooks(hm *server.HookManager) {
	// New user connection (NICK intro during burst or runtime)
	hm.Register(server.EventNick, func(srv *server.Server, msg *ircv3.P10Message) {
		if s.pc == nil { return }
		if !srv.BurstDone() { return }
		u := srv.Network().GetUser(msg.Source)
		if u == nil || u.IP == "" { return }
		if s.isExempt(u.IP) { return }
		s.mu.Lock()
		s.hostToIP[u.Host] = u.IP
		s.mu.Unlock()
		s.recordEvent(srv, u.IP, "connect", u.Nick)

		// Clone detection: count users sharing this IP
		clones := 0
		for _, other := range srv.Network().GetAllUsers() {
			if other.IP == u.IP { clones++ }
		}
		if clones > 1 {
			for i := 0; i < clones; i++ {
				s.recordEvent(srv, u.IP, "clone", u.Nick)
			}
		}
	})

	// Nick change (not initial intro)
	hm.Register(server.EventNick, func(srv *server.Server, msg *ircv3.P10Message) {
		if s.pc == nil || !srv.BurstDone() { return }
		u := srv.Network().GetUser(msg.Source)
		if u == nil || u.IP == "" || s.isExempt(u.IP) { return }
		s.recordEvent(srv, u.IP, "nick", u.Nick)
	})

	// Channel join
	hm.Register(server.EventJoin, func(srv *server.Server, msg *ircv3.P10Message) {
		if s.pc == nil || !srv.BurstDone() { return }
		u := srv.Network().GetUser(msg.Source)
		if u == nil || u.IP == "" || s.isExempt(u.IP) { return }
		channels := strings.Split(msg.Param(0), ",")
		for range channels {
			s.recordEvent(srv, u.IP, "join", u.Nick)
		}
	})

	// Messages (PRIVMSG)
	hm.Register(server.EventMessage, func(srv *server.Server, msg *ircv3.P10Message) {
		if s.pc == nil || !srv.BurstDone() || len(msg.Params) < 1 { return }
		u := srv.Network().GetUser(msg.Source)
		if u == nil || u.IP == "" || s.isExempt(u.IP) { return }

		s.recordEvent(srv, u.IP, "message", u.Nick)

		// Spam detection: hash the message body, track repeats
		body := msg.Trailing()
		if len(body) > 10 {
			h := sha256.Sum256([]byte(body))
			hash := hex.EncodeToString(h[:8])
			s.mu.Lock()
			rec := s.getOrCreate(u.IP)
			if rec.msgHashes == nil { rec.msgHashes = make(map[string]int) }
			rec.msgHashes[hash]++
			count := rec.msgHashes[hash]
			s.mu.Unlock()
			if count >= 3 {
				s.recordEvent(srv, u.IP, "spam", u.Nick)
			}
		}
	})

	// Auth failure detection via services NOTICE patterns
	// NickServ typically sends "Invalid password" or similar on auth failure.
	// We detect this from the perspective of failed SASL (EventAccount with empty).
	hm.Register(server.EventAccount, func(srv *server.Server, msg *ircv3.P10Message) {
		if s.pc == nil || !srv.BurstDone() { return }
		u := srv.Network().GetUser(msg.Source)
		if u == nil || u.IP == "" || s.isExempt(u.IP) { return }
		// AC with empty account = deauth / failed auth
		if u.Account == "" {
			s.recordEvent(srv, u.IP, "auth_fail", u.Nick)
		}
	})
}

// ── Core detection logic ───────────────────────────────────────────

func (s *Sentinel) recordEvent(srv *server.Server, ip, eventType, nick string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.stats.eventsProcessed++
	rec := s.getOrCreate(ip)
	now := time.Now()
	rec.lastUpdate = now

	if rec.events == nil { rec.events = make(map[string][]time.Time) }
	rec.events[eventType] = append(rec.events[eventType], now)

	// Evaluate each rule against this event type
	for _, rule := range s.rules {
		if rule.Event != eventType { continue }

		window := time.Duration(rule.WindowSecs) * time.Second
		cutoff := now.Add(-window)

		// Prune old timestamps and count
		ts := rec.events[eventType]
		i := 0
		for i < len(ts) && ts[i].Before(cutoff) { i++ }
		rec.events[eventType] = ts[i:]

		count := len(rec.events[eventType])
		if count >= rule.Threshold {
			rec.score += rule.Score
			s.stats.rulesTriggered++

			// Alert
			s.alertNoLock(srv, fmt.Sprintf(
				"\x0304[SENTINEL]\x03 %s (%s) triggered \x02%s\x02: %d/%d in %ds → score %d/%d",
				nick, ip, rule.Name, count, rule.Threshold,
				rule.WindowSecs, rec.score, s.listThreshold))

			// Reset the counter for this event type to prevent re-firing
			rec.events[eventType] = nil

			// Threshold check
			if rec.score >= s.listThreshold && !rec.listed {
				rec.listed = true
				s.stats.ipsListed++

				s.alertNoLock(srv, fmt.Sprintf(
					"\x0304[SENTINEL]\x03 \x02LISTING\x02 %s (score %d) — category %d",
					ip, rec.score, rule.Category))

				// Submit to Cerberus (async, outside lock)
				go s.submitToCerberus(ip, rule.Category,
					fmt.Sprintf("Sentinel: %s threshold exceeded (score %d)", rule.Name, rec.score))

				// Optional G-line
				if s.autoGline {
					s.stats.glinesIssued++
					mask := "*@" + ip
					go func() {
						_ = srv.SendP10(&ircv3.P10Message{
							Source:  srv.ServerNumeric(),
							Command: "GL",
							Params:  []string{"*", "+" + mask, fmt.Sprintf("%d", s.glineDuration), s.glineReason},
						})
					}()
					s.alertNoLock(srv, fmt.Sprintf(
						"\x0304[SENTINEL]\x03 G-lined %s (%ds)", mask, s.glineDuration))
				}
			}
		}
	}
}

func (s *Sentinel) getOrCreate(ip string) *ipRecord {
	rec, ok := s.records[ip]
	if !ok {
		rec = &ipRecord{
			events:    make(map[string][]time.Time),
			msgHashes: make(map[string]int),
		}
		s.records[ip] = rec
	}
	return rec
}

func (s *Sentinel) isExempt(ip string) bool {
	if s.exemptIPs[ip] { return true }
	// Exempt loopback and RFC1918
	parsed := net.ParseIP(ip)
	if parsed == nil { return false }
	return parsed.IsLoopback() || parsed.IsPrivate()
}

// ── Cerberus DNSBL submission ──────────────────────────────────────

func (s *Sentinel) submitToCerberus(ip string, category int, reason string) {
	if s.cerberusURL == "" || s.cerberusKey == "" { return }

	payload, _ := json.Marshal(map[string]interface{}{
		"ip":        ip,
		"category":  category,
		"source":    "sentinel",
		"reason":    reason,
		"ttl_hours": s.ttlHours,
	})

	req, err := http.NewRequest("POST", s.cerberusURL+"/api/add", bytes.NewReader(payload))
	if err != nil { return }
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", s.cerberusKey)

	resp, err := s.httpClient.Do(req)
	if err != nil {
		log.Printf("[sentinel] cerberus submit error: %v", err)
		return
	}
	resp.Body.Close()

	if resp.StatusCode == 200 {
		log.Printf("[sentinel] listed %s in cerberus (category %d)", ip, category)
	} else {
		log.Printf("[sentinel] cerberus returned %d for %s", resp.StatusCode, ip)
	}
}

// ── Background decay ───────────────────────────────────────────────

func (s *Sentinel) decayLoop() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-s.stopCh:
			return
		case <-ticker.C:
			s.mu.Lock()
			now := time.Now()
			for ip, rec := range s.records {
				if now.Sub(rec.lastUpdate) > s.decayWindow {
					delete(s.records, ip)
				}
			}
			// Also clean stale host→IP mappings (keep last 10000)
			if len(s.hostToIP) > 10000 {
				s.hostToIP = make(map[string]string)
			}
			s.mu.Unlock()
		}
	}
}

// ── Message handler (oper commands) ────────────────────────────────

func (s *Sentinel) HandleMessage(srv *server.Server, msg *ircv3.P10Message) {
	if s.pc == nil { return }

	// DNSBL weighted-scoring: parse MARK messages from Cathexis 1.5.6+.
	// Wire format: <server> MK <target> MARK :DNSBL|zone1|zone2
	// Legacy format from pre-1.5.6 Cathexis: same but with payload "DNSBL"
	// (no zones). That still scores — we treat it as a single-weight match
	// on whatever default weight is configured for the zone called "unknown".
	if (msg.Command == "MK" || msg.Command == "MARK") && s.dnsblEnabled {
		s.handleDNSBLMark(srv, msg)
		return
	}

	if msg.Command != "P" && msg.Command != "PRIVMSG" { return }
	if len(msg.Params) < 1 { return }
	target := msg.Param(0)
	if target != s.pc.Numeric && target != s.pc.Nick { return }

	parts := strings.Fields(msg.Trailing())
	if len(parts) == 0 { return }
	cmd := strings.ToUpper(parts[0])

	switch cmd {
	case "STATUS":
		s.mu.Lock()
		tracked := len(s.records)
		evts := s.stats.eventsProcessed
		rules := s.stats.rulesTriggered
		listed := s.stats.ipsListed
		glines := s.stats.glinesIssued
		s.mu.Unlock()
		_ = srv.SendNotice(s.pc.Numeric, msg.Source, fmt.Sprintf(
			"Tracking %d IPs | Events: %d | Rules triggered: %d | IPs listed: %d | G-lines: %d",
			tracked, evts, rules, listed, glines))

	case "CHECK":
		if len(parts) < 2 { _ = srv.SendNotice(s.pc.Numeric, msg.Source, "Usage: CHECK <ip>"); return }
		ip := parts[1]
		s.mu.Lock()
		rec, ok := s.records[ip]
		if !ok {
			s.mu.Unlock()
			_ = srv.SendNotice(s.pc.Numeric, msg.Source, fmt.Sprintf("%s: not tracked", ip))
			return
		}
		score := rec.score
		listed := rec.listed
		var active []string
		for evt, ts := range rec.events {
			if len(ts) > 0 { active = append(active, fmt.Sprintf("%s=%d", evt, len(ts))) }
		}
		s.mu.Unlock()
		_ = srv.SendNotice(s.pc.Numeric, msg.Source, fmt.Sprintf(
			"%s: score=%d/%d listed=%v events=[%s]",
			ip, score, s.listThreshold, listed, strings.Join(active, " ")))

	case "SUBMIT":
		if len(parts) < 3 {
			_ = srv.SendNotice(s.pc.Numeric, msg.Source, "Usage: SUBMIT <ip> <category> [reason]")
			return
		}
		ip := parts[1]
		if net.ParseIP(ip) == nil {
			_ = srv.SendNotice(s.pc.Numeric, msg.Source, "Invalid IP address")
			return
		}
		var cat int
		fmt.Sscanf(parts[2], "%d", &cat)
		if cat == 0 { cat = 19 }
		reason := "Manual oper submission"
		if len(parts) > 3 { reason = strings.Join(parts[3:], " ") }
		go s.submitToCerberus(ip, cat, reason)
		_ = srv.SendNotice(s.pc.Numeric, msg.Source, fmt.Sprintf("Submitted %s to Cerberus (category %d)", ip, cat))

	case "EXEMPT":
		if len(parts) < 2 { _ = srv.SendNotice(s.pc.Numeric, msg.Source, "Usage: EXEMPT <ip>"); return }
		s.mu.Lock()
		s.exemptIPs[parts[1]] = true
		delete(s.records, parts[1])
		s.mu.Unlock()
		_ = srv.SendNotice(s.pc.Numeric, msg.Source, fmt.Sprintf("Exempted %s", parts[1]))

	case "RULES":
		for _, r := range s.rules {
			_ = srv.SendNotice(s.pc.Numeric, msg.Source, fmt.Sprintf(
				"  %s: event=%s thresh=%d window=%ds score=%d cat=%d",
				r.Name, r.Event, r.Threshold, r.WindowSecs, r.Score, r.Category))
		}

	case "HELP":
		for _, l := range []string{
			"Sentinel — Network Abuse Detection",
			"Commands:",
			"  STATUS            Show tracking statistics",
			"  CHECK <ip>        Check score and events for an IP",
			"  SUBMIT <ip> <cat> [reason]  Manually submit IP to Cerberus",
			"  EXEMPT <ip>       Exempt an IP from tracking",
			"  RULES             List active detection rules",
		} {
			_ = srv.SendNotice(s.pc.Numeric, msg.Source, l)
		}
	}
}

func (s *Sentinel) alertNoLock(srv *server.Server, msg string) {
	if s.pc != nil && s.alertChannel != "" {
		_ = srv.SendPrivmsg(s.pc.Numeric, s.alertChannel, msg)
	}
}

func (s *Sentinel) Shutdown() {
	// Signal decayLoop to stop; safe to call once.
	select {
	case <-s.stopCh:
		// already closed
	default:
		close(s.stopCh)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	log.Printf("[%s] shutdown — tracked %d IPs, listed %d, glined %d",
		s.Name(), len(s.records), s.stats.ipsListed, s.stats.glinesIssued)
}

// ── DNSBL weighted scoring (Cathexis 1.5.6+) ────────────────────────

// handleDNSBLMark parses an extended DNSBL mark emitted by Cathexis's
// s_auth.c and applies weighted scoring + threshold actions.
//
// Wire format sent by Cathexis 1.5.6:
//   <serverprefix> MK <client-nick-or-numeric> MARK :DNSBL|zone1|zone2
//
// - param[0] = client identifier (nick or numeric)
// - param[1] = mark sub-type ("MARK" or "DNSBL_DATA")
// - param[2] = the mark payload, "<prefix>|<zone>|<zone>|..."
//
// Pre-1.5.6 Cathexis sends "DNSBL" with no zones; that case scores as
// a single unrecognized hit (no weight, no action) so behavior degrades
// gracefully when Cathexis hasn't been upgraded yet.
func (s *Sentinel) handleDNSBLMark(srv *server.Server, msg *ircv3.P10Message) {
	if len(msg.Params) < 3 {
		return
	}
	targetID := msg.Params[0]
	subType := strings.ToUpper(msg.Params[1])
	if subType != "MARK" && subType != "DNSBL_DATA" {
		return
	}
	payload := msg.Params[2]
	if payload == "" {
		return
	}

	// Only handle marks that start with the configured prefix (default "DNSBL").
	// Skip other mark types (GEOIP, WEBIRC, CVERSION, SSLCLIFP, KILL).
	parts := strings.Split(payload, "|")
	if !strings.EqualFold(parts[0], s.dnsblMarkPrefix) {
		return
	}

	// Resolve target to a user record so we can alert / gline meaningfully.
	u := srv.Network().GetUser(targetID)
	if u == nil {
		// Maybe it's a nick instead of a numeric; try that path.
		u = srv.Network().FindUserByNick(targetID)
	}
	if u == nil {
		return
	}
	if s.isExempt(u.IP) {
		return
	}

	// Score: sum configured weights for each recognized zone.
	zones := parts[1:]
	score := 0
	hit := make([]string, 0, len(zones))
	unknown := make([]string, 0)
	for _, z := range zones {
		z = strings.TrimSpace(strings.ToLower(z))
		if z == "" {
			continue
		}
		if w, ok := s.dnsblZoneWeights[z]; ok {
			score += w
			hit = append(hit, fmt.Sprintf("%s(w%d)", z, w))
		} else {
			unknown = append(unknown, z)
		}
	}

	// Log + count all hits (even zero-score ones are useful telemetry).
	s.mu.Lock()
	s.stats.eventsProcessed++
	s.mu.Unlock()

	if score == 0 && len(unknown) == 0 {
		// Bare "DNSBL" mark from pre-1.5.6 Cathexis, or no matching zones.
		// Quietly log and return without action.
		log.Printf("[sentinel/dnsbl] %s (%s) DNSBL-marked with no zone info (upgrade Cathexis to 1.5.6 for weighted scoring)",
			u.Nick, u.IP)
		return
	}

	mask := fmt.Sprintf("%s!%s@%s", u.Nick, u.Ident, u.Host)
	target := s.dnsblAlertChannel

	// GLINE at or above gline_threshold.
	if score >= s.dnsblGlineThreshold {
		s.mu.Lock()
		s.stats.glinesIssued++
		s.mu.Unlock()
		go func() {
			_ = srv.SendP10(&ircv3.P10Message{
				Source:  srv.ServerNumeric(),
				Command: "GL",
				Params: []string{
					"*",
					"+*@" + u.IP,
					fmt.Sprintf("%d", s.dnsblGlineDuration),
					s.dnsblGlineReason,
				},
			})
		}()
		if target != "" {
			_ = srv.SendPrivmsg(s.pc.Numeric, target, fmt.Sprintf(
				"\x0304[SENTINEL/DNSBL GLINE]\x03 %s score=%d zones=[%s] — G-lined *@%s for %ds",
				mask, score, strings.Join(hit, ", "), u.IP, s.dnsblGlineDuration))
		}
		log.Printf("[sentinel/dnsbl] GLINE %s score=%d zones=[%s]",
			mask, score, strings.Join(hit, ", "))
		return
	}

	// WARN between warn_threshold and gline_threshold.
	if score >= s.dnsblWarnThreshold {
		if target != "" {
			_ = srv.SendPrivmsg(s.pc.Numeric, target, fmt.Sprintf(
				"\x0307[SENTINEL/DNSBL WARN]\x03 %s score=%d zones=[%s] (warn=%d gline=%d)",
				mask, score, strings.Join(hit, ", "),
				s.dnsblWarnThreshold, s.dnsblGlineThreshold))
		}
		log.Printf("[sentinel/dnsbl] WARN %s score=%d zones=[%s]",
			mask, score, strings.Join(hit, ", "))
		return
	}

	// Below warn threshold — just log for telemetry.
	if len(hit) > 0 {
		log.Printf("[sentinel/dnsbl] %s score=%d zones=[%s] (under warn=%d)",
			mask, score, strings.Join(hit, ", "), s.dnsblWarnThreshold)
	}
	if len(unknown) > 0 {
		log.Printf("[sentinel/dnsbl] %s unknown zones in mark: [%s] (add to dnsbl_scoring.zones to score)",
			mask, strings.Join(unknown, ", "))
	}
}
