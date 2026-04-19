// Copyright (c) Cathexis Development
// SPDX-License-Identifier: GPL-2.0-only
//
// modules/rootserv.go — Services root administration.

package modules

import (
	"database/sql"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/brandontroidl/noesis/ircv3"
	"github.com/brandontroidl/noesis/network"
	"github.com/brandontroidl/noesis/server"

	_ "github.com/mattn/go-sqlite3"
)

type RootServ struct {
	pc       *server.PseudoClient
	roots    map[string]bool
	admins   map[string]bool
	auditDB  *sql.DB
	channels []string
}

func NewRootServ() *RootServ {
	return &RootServ{roots: make(map[string]bool), admins: make(map[string]bool)}
}

func (r *RootServ) Name() string { return "rootserv" }

func (r *RootServ) Init(s *server.Server) error {
	cfg := s.Config().Modules.RootServ
	if !cfg.Enabled {
		log.Printf("[%s] disabled", r.Name())
		return nil
	}
	for _, a := range cfg.RootAccounts {
		r.roots[strings.ToLower(a)] = true
	}
	for _, a := range cfg.AdminAccounts {
		r.admins[strings.ToLower(a)] = true
	}
	r.channels = cfg.AdminChannels
	if cfg.AuditDB != "" {
		db, err := sql.Open("sqlite3", cfg.AuditDB)
		if err != nil {
			return fmt.Errorf("open audit db: %w", err)
		}
		r.auditDB = db
		_, _ = db.Exec(`CREATE TABLE IF NOT EXISTS audit (id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT NOT NULL, account TEXT NOT NULL, command TEXT NOT NULL, args TEXT, result TEXT)`)
		_, _ = db.Exec(`CREATE INDEX IF NOT EXISTS audit_ts_idx ON audit(timestamp)`)
	}
	nick := cfg.Nick
	if nick == "" {
		nick = "RootServ"
	}
	ident := cfg.Ident
	if ident == "" {
		ident = "root"
	}
	gecos := cfg.Gecos
	if gecos == "" {
		gecos = "Services Root Administration"
	}
	pc, err := s.IntroducePseudoClient(nick, ident, s.Config().Server.Name, gecos, r)
	if err != nil {
		return fmt.Errorf("introduce %s: %w", nick, err)
	}
	r.pc = pc
	for _, ch := range r.channels {
		_ = s.JoinPseudoClient(pc.Numeric, ch)
	}
	log.Printf("[%s] initialized as %s (%s) roots=%d admins=%d", r.Name(), nick, pc.Numeric, len(r.roots), len(r.admins))
	return nil
}

func (r *RootServ) audit(account, command, args, result string) {
	if r.auditDB == nil {
		return
	}
	_, _ = r.auditDB.Exec(`INSERT INTO audit (timestamp, account, command, args, result) VALUES (?, ?, ?, ?, ?)`,
		time.Now().UTC().Format(time.RFC3339), account, command, args, result)
}

func (r *RootServ) isRoot(account string) bool {
	return r.roots[strings.ToLower(account)]
}

func (r *RootServ) isAdmin(account string) bool {
	return r.admins[strings.ToLower(account)] || r.isRoot(account)
}

// isRootUser checks if a user has root privileges.
// IRC opers are implicitly root (they already have full server control).
// Users with an account in the owners list are also root.
func (r *RootServ) isRootUser(u *network.User) bool {
	if u.IsOper() {
		return true
	}
	if u.Account != "" && r.isRoot(u.Account) {
		return true
	}
	return false
}

// isAdminUser checks if a user has admin privileges.
func (r *RootServ) isAdminUser(u *network.User) bool {
	if u.IsOper() {
		return true
	}
	if u.Account != "" && r.isAdmin(u.Account) {
		return true
	}
	return false
}

func (r *RootServ) HandleMessage(s *server.Server, msg *ircv3.P10Message) {
	if r.pc == nil || (msg.Command != "P" && msg.Command != "PRIVMSG") || len(msg.Params) < 2 {
		return
	}
	target := msg.Params[0]
	text := msg.Params[1]
	if !strings.EqualFold(target, r.pc.Nick) && !strings.EqualFold(target, r.pc.Numeric) {
		return
	}
	u := s.Network().GetUser(msg.Source)
	if u == nil {
		return
	}
	if u.Account == "" && !u.IsOper() {
		_ = s.SendNotice(r.pc.Numeric, msg.Source, "You must be authenticated or opered to use RootServ.")
		return
	}
	// Effective identity: use account if authed, fall back to nick for opers
	identity := u.Account
	if identity == "" {
		identity = u.Nick
	}
	parts := strings.Fields(text)
	if len(parts) == 0 {
		return
	}
	cmd := strings.ToUpper(parts[0])
	args := parts[1:]

	switch cmd {
	case "HELP":
		r.cmdHelp(s, msg.Source, identity)
	case "DIE":
		if !r.isRootUser(u) {
			_ = s.SendNotice(r.pc.Numeric, msg.Source, "Access denied. Root required.")
			return
		}
		reason := "Shutdown by " + identity
		if len(args) > 0 {
			reason = strings.Join(args, " ")
		}
		r.audit(identity, "DIE", reason, "executed")
		_ = s.SendNotice(r.pc.Numeric, msg.Source, "Shutting down: "+reason)
		log.Printf("[%s] DIE by %s: %s", r.Name(), identity, reason)
		s.Shutdown()
	case "RESTART":
		if !r.isRootUser(u) {
			_ = s.SendNotice(r.pc.Numeric, msg.Source, "Access denied. Root required.")
			return
		}
		r.audit(identity, "RESTART", "", "executed")
		_ = s.SendNotice(r.pc.Numeric, msg.Source, "Restarting services...")
		log.Printf("[%s] RESTART by %s", r.Name(), identity)
		s.Shutdown()
	case "REHASH":
		if !r.isRootUser(u) {
			_ = s.SendNotice(r.pc.Numeric, msg.Source, "Access denied. Root required.")
			return
		}
		r.audit(identity, "REHASH", "", "executed")
		_ = s.SendNotice(r.pc.Numeric, msg.Source, "Configuration rehash requested.")
		log.Printf("[%s] REHASH by %s", r.Name(), identity)
	case "RAW":
		if !r.isRootUser(u) {
			_ = s.SendNotice(r.pc.Numeric, msg.Source, "Access denied. Root required.")
			return
		}
		if len(args) == 0 {
			_ = s.SendNotice(r.pc.Numeric, msg.Source, "Usage: RAW <P10 line>")
			return
		}
		line := strings.Join(args, " ")
		r.audit(identity, "RAW", line, "sent")
		err := s.SendP10(ircv3.ParseP10Line(line))
		if err != nil {
			_ = s.SendNotice(r.pc.Numeric, msg.Source, fmt.Sprintf("Error: %v", err))
			return
		}
		_ = s.SendNotice(r.pc.Numeric, msg.Source, "Raw line sent.")
		log.Printf("[%s] RAW by %s: %s", r.Name(), identity, line)
	case "MODLIST":
		if !r.isRootUser(u) {
			_ = s.SendNotice(r.pc.Numeric, msg.Source, "Access denied. Root required.")
			return
		}
		_ = s.SendNotice(r.pc.Numeric, msg.Source, "Loaded modules:")
		for _, m := range s.Modules() {
			_ = s.SendNotice(r.pc.Numeric, msg.Source, fmt.Sprintf("  %s", m.Name()))
		}
	case "DBSAVE":
		if !r.isRootUser(u) {
			_ = s.SendNotice(r.pc.Numeric, msg.Source, "Access denied. Root required.")
			return
		}
		r.audit(identity, "DBSAVE", "", "executed")
		_ = s.SendNotice(r.pc.Numeric, msg.Source, "Database save forced.")
	case "SADMIN":
		if !r.isRootUser(u) {
			_ = s.SendNotice(r.pc.Numeric, msg.Source, "Access denied. Root required.")
			return
		}
		r.cmdSAdminSRoot(s, msg.Source, identity, args, r.admins, "services administrator")
	case "SROOT":
		if !r.isRootUser(u) {
			_ = s.SendNotice(r.pc.Numeric, msg.Source, "Access denied. Root required.")
			return
		}
		r.cmdSAdminSRoot(s, msg.Source, identity, args, r.roots, "services root")
	case "AUDIT":
		if !r.isAdminUser(u) {
			_ = s.SendNotice(r.pc.Numeric, msg.Source, "Access denied.")
			return
		}
		r.cmdAudit(s, msg.Source, args)
	case "WHOAMI":
		level := "none"
		if r.isRootUser(u) {
			level = "root"
		} else if r.isAdminUser(u) {
			level = "admin"
		}
		_ = s.SendNotice(r.pc.Numeric, msg.Source, fmt.Sprintf("Identity: %s | Privilege: %s", identity, level))
	case "SHOWCOMMANDS":
		r.cmdHelp(s, msg.Source, identity)
	case "HOLD":
		if !r.isRootUser(u) {
			_ = s.SendNotice(r.pc.Numeric, msg.Source, "Access denied. Root required.")
			return
		}
		if len(args) < 1 {
			_ = s.SendNotice(r.pc.Numeric, msg.Source, "Usage: HOLD <nick|#channel>")
			return
		}
		r.audit(identity, "HOLD", args[0], "set")
		_ = s.SendNotice(r.pc.Numeric, msg.Source, fmt.Sprintf("Hold set on %s.", args[0]))
	case "UNHOLD":
		if !r.isRootUser(u) {
			_ = s.SendNotice(r.pc.Numeric, msg.Source, "Access denied. Root required.")
			return
		}
		if len(args) < 1 {
			_ = s.SendNotice(r.pc.Numeric, msg.Source, "Usage: UNHOLD <nick|#channel>")
			return
		}
		r.audit(identity, "UNHOLD", args[0], "cleared")
		_ = s.SendNotice(r.pc.Numeric, msg.Source, fmt.Sprintf("Hold cleared on %s.", args[0]))
	case "SERVJOIN":
		if !r.isRootUser(u) {
			_ = s.SendNotice(r.pc.Numeric, msg.Source, "Access denied. Root required.")
			return
		}
		if len(args) < 1 {
			_ = s.SendNotice(r.pc.Numeric, msg.Source, "Usage: SERVJOIN <#channel>")
			return
		}
		ch := args[0]
		pcs := s.PseudoClients()
		count := 0
		for _, pc := range pcs {
			_ = s.JoinPseudoClient(pc.Numeric, ch)
			count++
		}
		r.audit(identity, "SERVJOIN", ch, fmt.Sprintf("%d clients", count))
		_ = s.SendNotice(r.pc.Numeric, msg.Source, fmt.Sprintf("Joined %d pseudo-clients to %s.", count, ch))
	case "SERVPART":
		if !r.isRootUser(u) {
			_ = s.SendNotice(r.pc.Numeric, msg.Source, "Access denied. Root required.")
			return
		}
		if len(args) < 1 {
			_ = s.SendNotice(r.pc.Numeric, msg.Source, "Usage: SERVPART <#channel>")
			return
		}
		ch := args[0]
		pcs := s.PseudoClients()
		count := 0
		for _, pc := range pcs {
			_ = s.PartPseudoClient(pc.Numeric, ch)
			count++
		}
		r.audit(identity, "SERVPART", ch, fmt.Sprintf("%d clients", count))
		_ = s.SendNotice(r.pc.Numeric, msg.Source, fmt.Sprintf("Parted %d pseudo-clients from %s.", count, ch))
	case "BOTJOIN":
		if !r.isAdmin(u.Account) {
			_ = s.SendNotice(r.pc.Numeric, msg.Source, "Access denied.")
			return
		}
		if len(args) < 2 {
			_ = s.SendNotice(r.pc.Numeric, msg.Source, "Usage: BOTJOIN <botnick> <#channel>")
			return
		}
		botNick := args[0]
		ch := args[1]
		pc := s.FindPseudoByNick(botNick)
		if pc == nil {
			_ = s.SendNotice(r.pc.Numeric, msg.Source, fmt.Sprintf("Bot %s not found.", botNick))
			return
		}
		_ = s.JoinPseudoClient(pc.Numeric, ch)
		r.audit(identity, "BOTJOIN", fmt.Sprintf("%s %s", botNick, ch), "")
		_ = s.SendNotice(r.pc.Numeric, msg.Source, fmt.Sprintf("Joined %s to %s.", botNick, ch))
	case "BOTPART":
		if !r.isAdmin(u.Account) {
			_ = s.SendNotice(r.pc.Numeric, msg.Source, "Access denied.")
			return
		}
		if len(args) < 2 {
			_ = s.SendNotice(r.pc.Numeric, msg.Source, "Usage: BOTPART <botnick> <#channel>")
			return
		}
		botNick := args[0]
		ch := args[1]
		pc := s.FindPseudoByNick(botNick)
		if pc == nil {
			_ = s.SendNotice(r.pc.Numeric, msg.Source, fmt.Sprintf("Bot %s not found.", botNick))
			return
		}
		_ = s.PartPseudoClient(pc.Numeric, ch)
		r.audit(identity, "BOTPART", fmt.Sprintf("%s %s", botNick, ch), "")
		_ = s.SendNotice(r.pc.Numeric, msg.Source, fmt.Sprintf("Parted %s from %s.", botNick, ch))
	case "BOTLIST":
		pcs := s.PseudoClients()
		_ = s.SendNotice(r.pc.Numeric, msg.Source, fmt.Sprintf("--- Acid Bots (%d) ---", len(pcs)))
		for _, pc := range pcs {
			_ = s.SendNotice(r.pc.Numeric, msg.Source, fmt.Sprintf("  %s (%s@%s)", pc.Nick, pc.Ident, pc.Host))
		}
		_ = s.SendNotice(r.pc.Numeric, msg.Source, "--- End of Bot List ---")
	default:
		_ = s.SendNotice(r.pc.Numeric, msg.Source, fmt.Sprintf("Unknown command: %s. Use HELP.", cmd))
	}
}

func (r *RootServ) cmdHelp(s *server.Server, target, account string) {
	if !r.isAdmin(account) {
		_ = s.SendNotice(r.pc.Numeric, target, "Access denied.")
		return
	}
	lines := []string{
		"RootServ — Services Root Administration",
		" ", "HELP  WHOAMI  SHOWCOMMANDS  AUDIT [N]",
	}
	if r.isRoot(account) {
		lines = append(lines, " ", "Root: DIE  RESTART  REHASH  RAW  DBSAVE  MODLIST",
			"      SADMIN ADD|DEL|LIST  SROOT ADD|DEL|LIST",
			"      HOLD <target>  UNHOLD <target>",
			"      SERVJOIN <#channel>  SERVPART <#channel>")
	}
	lines = append(lines, " ", "Bot Management:",
		"  BOTJOIN <botnick> <#channel>  — Join a bot to a channel",
		"  BOTPART <botnick> <#channel>  — Part a bot from a channel",
		"  BOTLIST                       — List all available bots")
	for _, l := range lines {
		_ = s.SendNotice(r.pc.Numeric, target, l)
	}
}

func (r *RootServ) cmdSAdminSRoot(s *server.Server, target, account string, args []string, m map[string]bool, label string) {
	if len(args) == 0 {
		_ = s.SendNotice(r.pc.Numeric, target, fmt.Sprintf("Usage: %s ADD|DEL|LIST [account]", strings.ToUpper(label)))
		return
	}
	switch strings.ToUpper(args[0]) {
	case "LIST":
		_ = s.SendNotice(r.pc.Numeric, target, fmt.Sprintf("%s accounts:", strings.Title(label)))
		for a := range m {
			_ = s.SendNotice(r.pc.Numeric, target, "  "+a)
		}
	case "ADD":
		if len(args) < 2 {
			return
		}
		a := strings.ToLower(args[1])
		m[a] = true
		r.audit(account, strings.ToUpper(label)+" ADD", a, "added")
		_ = s.SendNotice(r.pc.Numeric, target, fmt.Sprintf("Added %s as %s.", a, label))
	case "DEL":
		if len(args) < 2 {
			return
		}
		a := strings.ToLower(args[1])
		delete(m, a)
		r.audit(account, strings.ToUpper(label)+" DEL", a, "removed")
		_ = s.SendNotice(r.pc.Numeric, target, fmt.Sprintf("Removed %s from %s.", a, label))
	}
}

func (r *RootServ) cmdAudit(s *server.Server, target string, args []string) {
	if r.auditDB == nil {
		_ = s.SendNotice(r.pc.Numeric, target, "Audit logging not configured.")
		return
	}
	limit := 20
	if len(args) > 0 {
		fmt.Sscanf(args[0], "%d", &limit)
	}
	rows, err := r.auditDB.Query(`SELECT timestamp, account, command, args, result FROM audit ORDER BY id DESC LIMIT ?`, limit)
	if err != nil {
		_ = s.SendNotice(r.pc.Numeric, target, fmt.Sprintf("Error: %v", err))
		return
	}
	defer rows.Close()
	_ = s.SendNotice(r.pc.Numeric, target, fmt.Sprintf("Last %d audit entries:", limit))
	for rows.Next() {
		var ts, acct, cmd, a, res string
		_ = rows.Scan(&ts, &acct, &cmd, &a, &res)
		_ = s.SendNotice(r.pc.Numeric, target, fmt.Sprintf("  [%s] %s: %s %s (%s)", ts, acct, cmd, a, res))
	}
}

func (r *RootServ) Shutdown() {
	if r.auditDB != nil {
		_ = r.auditDB.Close()
	}
	log.Printf("[%s] shutdown", r.Name())
}
