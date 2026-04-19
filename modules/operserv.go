// Copyright (c) Cathexis Development
// SPDX-License-Identifier: GPL-2.0-only
//
// modules/operserv.go — Network operations service.
//
// Provides TRACE (user search), GLINE/SHUN/ZLINE management with
// persistent storage, AKILL (persistent bans surviving restart),
// CLONES (clone management with exemptions), and DEFCON (network
// emergency levels). Based on x3 OpServ, srvx mod-gline, NeoStats.

package modules

import (
	"database/sql"
	"fmt"
	"log"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/brandontroidl/noesis/ircv3"
	"github.com/brandontroidl/noesis/network"
	"github.com/brandontroidl/noesis/server"

	_ "github.com/mattn/go-sqlite3"
)

type OperServ struct {
	pc *server.PseudoClient
	db *sql.DB

	// DEFCON
	defconMu    sync.RWMutex
	defconLevel int // 5 = normal, 1 = full lockdown

	// Clone exemptions
	cloneExemptMu sync.RWMutex
	cloneExempts  map[string]int // host/IP -> allowed count
}

func NewOperServ() *OperServ {
	return &OperServ{
		defconLevel:  5,
		cloneExempts: make(map[string]int),
	}
}

func (o *OperServ) Name() string { return "operserv" }

func (o *OperServ) Init(s *server.Server) error {
	cfg := s.Config().Modules.OperServ
	if !cfg.Enabled {
		log.Printf("[%s] disabled", o.Name())
		return nil
	}

	if cfg.Database != "" {
		db, err := sql.Open("sqlite3", cfg.Database)
		if err != nil {
			return fmt.Errorf("open operserv db: %w", err)
		}
		o.db = db
		o.initDB()
		o.loadAkills(s)
		o.loadCloneExempts()
	}

	nick := cfg.Nick
	if nick == "" {
		nick = "OperServ"
	}
	ident := cfg.Ident
	if ident == "" {
		ident = "oper"
	}
	gecos := cfg.Gecos
	if gecos == "" {
		gecos = "Network Operations Service"
	}

	pc, err := s.IntroducePseudoClient(nick, ident, s.Config().Server.Name, gecos, o)
	if err != nil {
		return fmt.Errorf("introduce %s: %w", nick, err)
	}
	o.pc = pc

	for _, ch := range cfg.Channels {
		_ = s.JoinPseudoClient(pc.Numeric, ch)
	}

	log.Printf("[%s] initialized as %s (%s) defcon=%d", o.Name(), nick, pc.Numeric, o.defconLevel)
	return nil
}

func (o *OperServ) initDB() {
	if o.db == nil {
		return
	}
	_, _ = o.db.Exec(`CREATE TABLE IF NOT EXISTS akills (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		mask TEXT NOT NULL UNIQUE,
		reason TEXT NOT NULL,
		setter TEXT NOT NULL,
		set_time TEXT NOT NULL,
		duration INTEGER NOT NULL,
		expires TEXT NOT NULL
	)`)
	_, _ = o.db.Exec(`CREATE TABLE IF NOT EXISTS clone_exempts (
		host TEXT PRIMARY KEY,
		allowed INTEGER NOT NULL,
		setter TEXT NOT NULL,
		set_time TEXT NOT NULL
	)`)
	_, _ = o.db.Exec(`CREATE TABLE IF NOT EXISTS seen (
		account TEXT PRIMARY KEY,
		nick TEXT NOT NULL,
		host TEXT,
		quit_msg TEXT,
		last_seen TEXT NOT NULL
	)`)
}

func (o *OperServ) loadAkills(s *server.Server) {
	if o.db == nil {
		return
	}
	rows, err := o.db.Query(`SELECT mask, reason, duration FROM akills WHERE expires > ?`, time.Now().UTC().Format(time.RFC3339))
	if err != nil {
		return
	}
	defer rows.Close()
	count := 0
	for rows.Next() {
		var mask, reason string
		var dur int
		_ = rows.Scan(&mask, &reason, &dur)
		_ = s.SendP10(&ircv3.P10Message{
			Source: s.ServerNumeric(), Command: "GL",
			Params: []string{"*", "+" + mask, fmt.Sprintf("%d", dur), reason},
		})
		count++
	}
	if count > 0 {
		log.Printf("[%s] re-applied %d akills", o.Name(), count)
	}
}

func (o *OperServ) loadCloneExempts() {
	if o.db == nil {
		return
	}
	rows, err := o.db.Query(`SELECT host, allowed FROM clone_exempts`)
	if err != nil {
		return
	}
	defer rows.Close()
	for rows.Next() {
		var host string
		var allowed int
		_ = rows.Scan(&host, &allowed)
		o.cloneExempts[host] = allowed
	}
}

func (o *OperServ) HandleMessage(s *server.Server, msg *ircv3.P10Message) {
	if o.pc == nil || (msg.Command != "P" && msg.Command != "PRIVMSG") || len(msg.Params) < 2 {
		return
	}
	if !strings.EqualFold(msg.Params[0], o.pc.Nick) && !strings.EqualFold(msg.Params[0], o.pc.Numeric) {
		return
	}
	u := s.Network().GetUser(msg.Source)
	if u == nil {
		return
	}
	if !strings.Contains(u.Modes, "o") {
		_ = s.SendNotice(o.pc.Numeric, msg.Source, "Access denied. You must be an IRC operator.")
		return
	}

	parts := strings.Fields(msg.Params[1])
	if len(parts) == 0 {
		return
	}
	cmd := strings.ToUpper(parts[0])
	args := parts[1:]

	switch cmd {
	case "HELP":
		o.cmdHelp(s, msg.Source)
	case "TRACE":
		o.cmdTrace(s, msg.Source, args)
	case "GLINE":
		o.cmdGline(s, msg.Source, u, args)
	case "UNGLINE":
		o.cmdUngline(s, msg.Source, u, args)
	case "SHUN":
		o.cmdShun(s, msg.Source, u, args)
	case "UNSHUN":
		o.cmdUnshun(s, msg.Source, u, args)
	case "AKILL":
		o.cmdAkill(s, msg.Source, u, args)
	case "CLONES":
		o.cmdClones(s, msg.Source, u, args)
	case "DEFCON":
		o.cmdDefcon(s, msg.Source, u, args)
	case "SEEN":
		o.cmdSeen(s, msg.Source, args)
	case "CALC":
		o.cmdCalc(s, msg.Source, args)
	default:
		_ = s.SendNotice(o.pc.Numeric, msg.Source, fmt.Sprintf("Unknown command: %s. Use HELP.", cmd))
	}
}

func (o *OperServ) notice(s *server.Server, target, text string) {
	_ = s.SendNotice(o.pc.Numeric, target, text)
}

// ─── HELP ───

func (o *OperServ) cmdHelp(s *server.Server, target string) {
	for _, l := range []string{
		"\x02OperServ — Network Operations Service\x02",
		" ",
		"\x02User Search:\x02",
		"  TRACE <criteria>     Search users (nick/host/ip/account/server/realname/modes/channel)",
		"    Examples: TRACE nick=*bot*  TRACE ip=192.168.*  TRACE server=irc.*",
		"    Criteria: nick= host= ip= account= server= realname= modes= channel=",
		"    Actions: COUNT PRINT GLINE KILL (default: PRINT)",
		" ",
		"\x02Ban Management:\x02",
		"  GLINE <mask> <duration> <reason>    Set a G-line",
		"  UNGLINE <mask>                      Remove a G-line",
		"  SHUN <mask> <duration> <reason>     Set a shun",
		"  UNSHUN <mask>                       Remove a shun",
		" ",
		"\x02Persistent Bans:\x02",
		"  AKILL ADD <mask> <duration> <reason>   Add persistent ban",
		"  AKILL DEL <mask>                       Remove persistent ban",
		"  AKILL LIST [pattern]                   List persistent bans",
		"  AKILL COUNT                            Count persistent bans",
		" ",
		"\x02Clone Management:\x02",
		"  CLONES LIST                          Show current clones",
		"  CLONES EXEMPT ADD <host> <count>     Add clone exemption",
		"  CLONES EXEMPT DEL <host>             Remove clone exemption",
		"  CLONES EXEMPT LIST                   List exemptions",
		" ",
		"\x02Network Emergency:\x02",
		"  DEFCON [1-5]                         View/set DEFCON level",
		"    5=normal 4=no new channels 3=force +R 2=no new users 1=full lockdown",
		" ",
		"\x02Misc:\x02",
		"  SEEN <nick|account>                  Last seen info",
		"  CALC <expression>                    Simple math",
	} {
		o.notice(s, target, l)
	}
}

// ─── TRACE ───

func (o *OperServ) cmdTrace(s *server.Server, target string, args []string) {
	if len(args) == 0 {
		o.notice(s, target, "Usage: TRACE <criteria> [action]")
		o.notice(s, target, "  Criteria: nick= host= ip= account= server= realname= modes= channel=")
		o.notice(s, target, "  Actions: COUNT PRINT GLINE KILL (default: PRINT)")
		return
	}

	// Parse criteria and action
	criteria := make(map[string]string)
	action := "PRINT"
	limit := 50

	for _, arg := range args {
		upper := strings.ToUpper(arg)
		if upper == "COUNT" || upper == "PRINT" || upper == "GLINE" || upper == "KILL" {
			action = upper
			continue
		}
		if strings.HasPrefix(upper, "LIMIT=") {
			fmt.Sscanf(arg[6:], "%d", &limit)
			continue
		}
		if idx := strings.Index(arg, "="); idx > 0 {
			key := strings.ToLower(arg[:idx])
			val := arg[idx+1:]
			criteria[key] = val
		}
	}

	if len(criteria) == 0 {
		o.notice(s, target, "Error: No search criteria specified.")
		return
	}

	users := s.Network().GetAllUsers()
	var matches []*struct {
		nick, ident, host, ip, account, server, realname, modes string
		numeric                                                  string
	}

	for _, u := range users {
		if o.matchesCriteria(s, u, criteria) {
			matches = append(matches, &struct {
				nick, ident, host, ip, account, server, realname, modes string
				numeric                                                  string
			}{u.Nick, u.Ident, u.Host, u.IP, u.Account, u.Server, u.Gecos, u.Modes, u.Numeric})
		}
	}

	switch action {
	case "COUNT":
		o.notice(s, target, fmt.Sprintf("TRACE matched \x02%d\x02 user(s).", len(matches)))
	case "PRINT":
		o.notice(s, target, fmt.Sprintf("TRACE results (\x02%d\x02 match(es)):", len(matches)))
		for i, m := range matches {
			if i >= limit {
				o.notice(s, target, fmt.Sprintf("  ... and %d more (use LIMIT= to increase)", len(matches)-limit))
				break
			}
			acct := m.account
			if acct == "" {
				acct = "(none)"
			}
			o.notice(s, target, fmt.Sprintf("  %s (%s@%s) [%s] acct=%s server=%s", m.nick, m.ident, m.host, m.ip, acct, m.server))
		}
	case "GLINE":
		count := 0
		for _, m := range matches {
			mask := fmt.Sprintf("*@%s", m.ip)
			_ = s.SendP10(&ircv3.P10Message{
				Source: s.ServerNumeric(), Command: "GL",
				Params: []string{"*", "+" + mask, "3600", "TRACE gline"},
			})
			count++
		}
		o.notice(s, target, fmt.Sprintf("TRACE glined \x02%d\x02 user(s).", count))
	case "KILL":
		count := 0
		for _, m := range matches {
			_ = s.SendP10(&ircv3.P10Message{
				Source: o.pc.Numeric, Command: "D",
				Params: []string{m.numeric, "TRACE kill"},
			})
			count++
		}
		o.notice(s, target, fmt.Sprintf("TRACE killed \x02%d\x02 user(s).", count))
	}
}

func (o *OperServ) matchesCriteria(s *server.Server, u *network.User, criteria map[string]string) bool {
	for key, pattern := range criteria {
		switch key {
		case "nick":
			if !matchWild(pattern, u.Nick) {
				return false
			}
		case "host":
			if !matchWild(pattern, u.Host) && !matchWild(pattern, u.CloakHost) {
				return false
			}
		case "ip":
			if !matchWild(pattern, u.IP) {
				return false
			}
		case "account":
			if !matchWild(pattern, u.Account) {
				return false
			}
		case "server":
			srv := s.Network().GetServer(u.Server)
			srvName := u.Server
			if srv != nil {
				srvName = srv.Name
			}
			if !matchWild(pattern, srvName) {
				return false
			}
		case "realname":
			if !matchWild(pattern, u.Gecos) {
				return false
			}
		case "modes":
			for _, c := range pattern {
				if !strings.ContainsRune(u.Modes, c) {
					return false
				}
			}
		case "channel":
			found := false
			for ch := range u.Channels {
				if matchWild(pattern, ch) {
					found = true
					break
				}
			}
			if !found {
				return false
			}
		}
	}
	return true
}

// ─── GLINE / UNGLINE ───

func (o *OperServ) cmdGline(s *server.Server, target string, u *network.User, args []string) {
	if len(args) < 3 {
		o.notice(s, target, "Usage: GLINE <mask> <duration> <reason>")
		o.notice(s, target, "  Duration: 1h, 30m, 7d, 1h30m, etc.")
		return
	}
	mask := args[0]
	dur, err := parseDuration(args[1])
	if err != nil {
		o.notice(s, target, fmt.Sprintf("Invalid duration: %s", args[1]))
		return
	}
	reason := strings.Join(args[2:], " ")

	_ = s.SendP10(&ircv3.P10Message{
		Source: s.ServerNumeric(), Command: "GL",
		Params: []string{"*", "+" + mask, fmt.Sprintf("%d", int(dur.Seconds())), reason},
	})
	o.notice(s, target, fmt.Sprintf("G-line set on \x02%s\x02 for %s: %s", mask, dur, reason))
	log.Printf("[%s] GLINE %s %s by %s: %s", o.Name(), mask, dur, u.Account, reason)
}

func (o *OperServ) cmdUngline(s *server.Server, target string, u *network.User, args []string) {
	if len(args) < 1 {
		o.notice(s, target, "Usage: UNGLINE <mask>")
		return
	}
	_ = s.SendP10(&ircv3.P10Message{
		Source: s.ServerNumeric(), Command: "GL",
		Params: []string{"*", "-" + args[0], "0", "Removed"},
	})
	o.notice(s, target, fmt.Sprintf("G-line removed on \x02%s\x02.", args[0]))
}

// ─── SHUN / UNSHUN ───

func (o *OperServ) cmdShun(s *server.Server, target string, u *network.User, args []string) {
	if len(args) < 3 {
		o.notice(s, target, "Usage: SHUN <mask> <duration> <reason>")
		return
	}
	mask := args[0]
	dur, err := parseDuration(args[1])
	if err != nil {
		o.notice(s, target, fmt.Sprintf("Invalid duration: %s", args[1]))
		return
	}
	reason := strings.Join(args[2:], " ")

	_ = s.SendP10(&ircv3.P10Message{
		Source: s.ServerNumeric(), Command: "SU",
		Params: []string{"*", "+" + mask, fmt.Sprintf("%d", int(dur.Seconds())), reason},
	})
	o.notice(s, target, fmt.Sprintf("Shun set on \x02%s\x02 for %s: %s", mask, dur, reason))
}

func (o *OperServ) cmdUnshun(s *server.Server, target string, u *network.User, args []string) {
	if len(args) < 1 {
		o.notice(s, target, "Usage: UNSHUN <mask>")
		return
	}
	_ = s.SendP10(&ircv3.P10Message{
		Source: s.ServerNumeric(), Command: "SU",
		Params: []string{"*", "-" + args[0], "0", "Removed"},
	})
	o.notice(s, target, fmt.Sprintf("Shun removed on \x02%s\x02.", args[0]))
}

// ─── AKILL (persistent) ───

func (o *OperServ) cmdAkill(s *server.Server, target string, u *network.User, args []string) {
	if len(args) == 0 {
		o.notice(s, target, "Usage: AKILL ADD|DEL|LIST|COUNT [args]")
		return
	}
	sub := strings.ToUpper(args[0])
	switch sub {
	case "ADD":
		if len(args) < 4 {
			o.notice(s, target, "Usage: AKILL ADD <mask> <duration> <reason>")
			return
		}
		mask := args[1]
		dur, err := parseDuration(args[2])
		if err != nil {
			o.notice(s, target, fmt.Sprintf("Invalid duration: %s", args[2]))
			return
		}
		reason := strings.Join(args[3:], " ")
		now := time.Now().UTC()
		expires := now.Add(dur)
		setter := u.Account
		if setter == "" {
			setter = u.Nick
		}

		// Store in DB
		if o.db != nil {
			_, err := o.db.Exec(`INSERT OR REPLACE INTO akills (mask, reason, setter, set_time, duration, expires) VALUES (?, ?, ?, ?, ?, ?)`,
				mask, reason, setter, now.Format(time.RFC3339), int(dur.Seconds()), expires.Format(time.RFC3339))
			if err != nil {
				o.notice(s, target, fmt.Sprintf("Database error: %v", err))
				return
			}
		}

		// Apply immediately
		_ = s.SendP10(&ircv3.P10Message{
			Source: s.ServerNumeric(), Command: "GL",
			Params: []string{"*", "+" + mask, fmt.Sprintf("%d", int(dur.Seconds())), reason},
		})
		o.notice(s, target, fmt.Sprintf("AKILL added: \x02%s\x02 expires %s (%s)", mask, expires.Format("2006-01-02 15:04"), reason))
		log.Printf("[%s] AKILL ADD %s by %s: %s", o.Name(), mask, setter, reason)

	case "DEL":
		if len(args) < 2 {
			o.notice(s, target, "Usage: AKILL DEL <mask>")
			return
		}
		mask := args[1]
		if o.db != nil {
			res, _ := o.db.Exec(`DELETE FROM akills WHERE mask = ?`, mask)
			n, _ := res.RowsAffected()
			if n == 0 {
				o.notice(s, target, fmt.Sprintf("AKILL \x02%s\x02 not found.", mask))
				return
			}
		}
		// Remove the gline too
		_ = s.SendP10(&ircv3.P10Message{
			Source: s.ServerNumeric(), Command: "GL",
			Params: []string{"*", "-" + mask, "0", "AKILL removed"},
		})
		o.notice(s, target, fmt.Sprintf("AKILL removed: \x02%s\x02", mask))

	case "LIST":
		if o.db == nil {
			o.notice(s, target, "Database not configured.")
			return
		}
		pattern := "%"
		if len(args) > 1 {
			pattern = "%" + args[1] + "%"
		}
		rows, err := o.db.Query(`SELECT mask, reason, setter, set_time, expires FROM akills WHERE mask LIKE ? AND expires > ? ORDER BY set_time DESC LIMIT 50`,
			pattern, time.Now().UTC().Format(time.RFC3339))
		if err != nil {
			o.notice(s, target, fmt.Sprintf("Error: %v", err))
			return
		}
		defer rows.Close()
		o.notice(s, target, "\x02Active AKILLs:\x02")
		ct := 0
		for rows.Next() {
			var mask, reason, setter, setTime, expires string
			_ = rows.Scan(&mask, &reason, &setter, &setTime, &expires)
			o.notice(s, target, fmt.Sprintf("  %s — %s (by %s, expires %s)", mask, reason, setter, expires[:16]))
			ct++
		}
		if ct == 0 {
			o.notice(s, target, "  (none)")
		}
		o.notice(s, target, fmt.Sprintf("End of AKILL list (%d entries).", ct))

	case "COUNT":
		if o.db == nil {
			o.notice(s, target, "Database not configured.")
			return
		}
		var count int
		_ = o.db.QueryRow(`SELECT COUNT(*) FROM akills WHERE expires > ?`, time.Now().UTC().Format(time.RFC3339)).Scan(&count)
		o.notice(s, target, fmt.Sprintf("\x02%d\x02 active AKILL(s).", count))
	}
}

// ─── CLONES ───

func (o *OperServ) cmdClones(s *server.Server, target string, u *network.User, args []string) {
	if len(args) == 0 {
		o.notice(s, target, "Usage: CLONES LIST | EXEMPT ADD|DEL|LIST")
		return
	}
	sub := strings.ToUpper(args[0])
	switch sub {
	case "LIST":
		users := s.Network().GetAllUsers()
		hosts := make(map[string][]string)
		for _, usr := range users {
			hosts[usr.Host] = append(hosts[usr.Host], usr.Nick)
		}
		o.notice(s, target, "\x02Clones (2+ per host):\x02")
		ct := 0
		for host, nicks := range hosts {
			if len(nicks) >= 2 {
				o.cloneExemptMu.RLock()
				exempt := o.cloneExempts[host]
				o.cloneExemptMu.RUnlock()
				tag := ""
				if exempt > 0 {
					tag = fmt.Sprintf(" [exempt:%d]", exempt)
				}
				o.notice(s, target, fmt.Sprintf("  %s (%d): %s%s", host, len(nicks), strings.Join(nicks, ", "), tag))
				ct++
			}
		}
		if ct == 0 {
			o.notice(s, target, "  (none)")
		}

	case "EXEMPT":
		if len(args) < 2 {
			o.notice(s, target, "Usage: CLONES EXEMPT ADD|DEL|LIST [host] [count]")
			return
		}
		esub := strings.ToUpper(args[1])
		switch esub {
		case "ADD":
			if len(args) < 4 {
				o.notice(s, target, "Usage: CLONES EXEMPT ADD <host> <count>")
				return
			}
			host := args[2]
			count, _ := strconv.Atoi(args[3])
			if count < 2 {
				count = 2
			}
			o.cloneExemptMu.Lock()
			o.cloneExempts[host] = count
			o.cloneExemptMu.Unlock()
			setter := u.Account
			if setter == "" {
				setter = u.Nick
			}
			if o.db != nil {
				_, _ = o.db.Exec(`INSERT OR REPLACE INTO clone_exempts (host, allowed, setter, set_time) VALUES (?, ?, ?, ?)`,
					host, count, setter, time.Now().UTC().Format(time.RFC3339))
			}
			o.notice(s, target, fmt.Sprintf("Clone exemption set: %s allowed %d.", host, count))

		case "DEL":
			if len(args) < 3 {
				o.notice(s, target, "Usage: CLONES EXEMPT DEL <host>")
				return
			}
			host := args[2]
			o.cloneExemptMu.Lock()
			delete(o.cloneExempts, host)
			o.cloneExemptMu.Unlock()
			if o.db != nil {
				_, _ = o.db.Exec(`DELETE FROM clone_exempts WHERE host = ?`, host)
			}
			o.notice(s, target, fmt.Sprintf("Clone exemption removed: %s", host))

		case "LIST":
			o.cloneExemptMu.RLock()
			defer o.cloneExemptMu.RUnlock()
			o.notice(s, target, fmt.Sprintf("\x02Clone exemptions (%d):\x02", len(o.cloneExempts)))
			for host, count := range o.cloneExempts {
				o.notice(s, target, fmt.Sprintf("  %s: %d allowed", host, count))
			}
		}
	}
}

// ─── DEFCON ───

func (o *OperServ) cmdDefcon(s *server.Server, target string, u *network.User, args []string) {
	if len(args) == 0 {
		o.defconMu.RLock()
		level := o.defconLevel
		o.defconMu.RUnlock()
		desc := defconDesc(level)
		o.notice(s, target, fmt.Sprintf("Current DEFCON level: \x02%d\x02 (%s)", level, desc))
		return
	}

	level, err := strconv.Atoi(args[0])
	if err != nil || level < 1 || level > 5 {
		o.notice(s, target, "Usage: DEFCON [1-5]")
		return
	}

	o.defconMu.Lock()
	old := o.defconLevel
	o.defconLevel = level
	o.defconMu.Unlock()

	desc := defconDesc(level)
	o.notice(s, target, fmt.Sprintf("DEFCON changed from \x02%d\x02 to \x02%d\x02 (%s)", old, level, desc))
	log.Printf("[%s] DEFCON %d -> %d by %s", o.Name(), old, level, u.Account)

	// Apply network-wide effects
	if level <= 3 && old > 3 {
		// Force +R (registered only) on all channels
		o.notice(s, target, "DEFCON 3: Network-wide +R would be enforced (placeholder).")
	}
	if level <= 2 && old > 2 {
		o.notice(s, target, "DEFCON 2: New unregistered connections would be refused (placeholder).")
	}
	if level == 1 {
		o.notice(s, target, "DEFCON 1: FULL LOCKDOWN — no new connections, no channel creation, no nick changes (placeholder).")
	}
}

func defconDesc(level int) string {
	switch level {
	case 5:
		return "Normal operations"
	case 4:
		return "No new channel registration"
	case 3:
		return "Force +R on channels"
	case 2:
		return "Refuse new unregistered connections"
	case 1:
		return "FULL LOCKDOWN"
	default:
		return "Unknown"
	}
}

// ─── SEEN ───

func (o *OperServ) cmdSeen(s *server.Server, target string, args []string) {
	if len(args) < 1 {
		o.notice(s, target, "Usage: SEEN <nick|account>")
		return
	}
	query := args[0]

	// Check online first
	u := s.Network().FindUserByNick(query)
	if u != nil {
		o.notice(s, target, fmt.Sprintf("\x02%s\x02 is online right now (%s@%s).", u.Nick, u.Ident, u.Host))
		return
	}

	// Check database
	if o.db == nil {
		o.notice(s, target, "Seen database not configured.")
		return
	}
	var nick, host, quitMsg, lastSeen string
	err := o.db.QueryRow(`SELECT nick, host, quit_msg, last_seen FROM seen WHERE account = ? OR nick = ? ORDER BY last_seen DESC LIMIT 1`,
		query, query).Scan(&nick, &host, &quitMsg, &lastSeen)
	if err != nil {
		o.notice(s, target, fmt.Sprintf("\x02%s\x02 has not been seen.", query))
		return
	}
	t, _ := time.Parse(time.RFC3339, lastSeen)
	ago := time.Since(t).Round(time.Second)
	o.notice(s, target, fmt.Sprintf("\x02%s\x02 was last seen %s ago (%s@%s) — %s", nick, ago, nick, host, quitMsg))
}

// RecordSeen records a user's last seen info on quit.
func (o *OperServ) RecordSeen(account, nick, host, quitMsg string) {
	if o.db == nil || account == "" {
		return
	}
	_, _ = o.db.Exec(`INSERT OR REPLACE INTO seen (account, nick, host, quit_msg, last_seen) VALUES (?, ?, ?, ?, ?)`,
		account, nick, host, quitMsg, time.Now().UTC().Format(time.RFC3339))
}

// ─── CALC ───

func (o *OperServ) cmdCalc(s *server.Server, target string, args []string) {
	if len(args) == 0 {
		o.notice(s, target, "Usage: CALC <expression>")
		return
	}
	expr := strings.Join(args, " ")
	result, err := evalSimple(expr)
	if err != nil {
		o.notice(s, target, fmt.Sprintf("Error: %v", err))
		return
	}
	o.notice(s, target, fmt.Sprintf("%s = \x02%s\x02", expr, result))
}

// evalSimple evaluates basic arithmetic: +, -, *, /, %, **
func evalSimple(expr string) (string, error) {
	// Security: only allow digits, operators, spaces, parens, dots
	safe := regexp.MustCompile(`^[0-9+\-*/%. ()]+$`)
	if !safe.MatchString(expr) {
		return "", fmt.Errorf("invalid characters in expression")
	}

	// Simple two-operand eval
	expr = strings.TrimSpace(expr)
	for _, op := range []string{"+", "-", "*", "/", "%"} {
		// Find the LAST occurrence for left-to-right evaluation
		idx := strings.LastIndex(expr, op)
		if idx > 0 && idx < len(expr)-1 {
			left := strings.TrimSpace(expr[:idx])
			right := strings.TrimSpace(expr[idx+1:])
			a, err1 := strconv.ParseFloat(left, 64)
			b, err2 := strconv.ParseFloat(right, 64)
			if err1 == nil && err2 == nil {
				var result float64
				switch op {
				case "+":
					result = a + b
				case "-":
					result = a - b
				case "*":
					result = a * b
				case "/":
					if b == 0 {
						return "", fmt.Errorf("division by zero")
					}
					result = a / b
				case "%":
					if b == 0 {
						return "", fmt.Errorf("division by zero")
					}
					result = float64(int(a) % int(b))
				}
				if result == float64(int(result)) {
					return strconv.Itoa(int(result)), nil
				}
				return fmt.Sprintf("%.6g", result), nil
			}
		}
	}

	// Maybe it's just a number
	if _, err := strconv.ParseFloat(expr, 64); err == nil {
		return expr, nil
	}
	return "", fmt.Errorf("cannot evaluate: %s", expr)
}

// ─── HOOKS ───

func (o *OperServ) RegisterHooks(hm *server.HookManager) {
	// Track QUIT for SEEN
	hm.Register(server.EventQuit, func(s *server.Server, msg *ircv3.P10Message) {
		if o.pc == nil {
			return
		}
		u := s.Network().GetUser(msg.Source)
		if u == nil || u.Account == "" {
			return
		}
		reason := ""
		if len(msg.Params) > 0 {
			reason = msg.Params[0]
		}
		o.RecordSeen(u.Account, u.Nick, u.Host, reason)
	})

	// DEFCON enforcement on new connections
	hm.Register(server.EventNick, func(s *server.Server, msg *ircv3.P10Message) {
		if o.pc == nil {
			return
		}
		o.defconMu.RLock()
		level := o.defconLevel
		o.defconMu.RUnlock()

		if level <= 2 {
			u := s.Network().GetUser(msg.Source)
			if u != nil && u.Account == "" {
				_ = s.SendP10(&ircv3.P10Message{
					Source: o.pc.Numeric, Command: "D",
					Params: []string{msg.Source, fmt.Sprintf("DEFCON %d: New connections restricted", level)},
				})
			}
		}
	})
}

// ─── Duration parsing ───

func parseDuration(s string) (time.Duration, error) {
	s = strings.ToLower(s)
	// Try standard Go duration first
	if d, err := time.ParseDuration(s); err == nil {
		return d, nil
	}
	// Try custom: 7d, 1d12h, etc.
	total := time.Duration(0)
	current := ""
	for _, c := range s {
		if c >= '0' && c <= '9' {
			current += string(c)
		} else {
			n, err := strconv.Atoi(current)
			if err != nil {
				return 0, fmt.Errorf("invalid duration: %s", s)
			}
			current = ""
			switch c {
			case 'd':
				total += time.Duration(n) * 24 * time.Hour
			case 'h':
				total += time.Duration(n) * time.Hour
			case 'm':
				total += time.Duration(n) * time.Minute
			case 's':
				total += time.Duration(n) * time.Second
			default:
				return 0, fmt.Errorf("unknown unit: %c", c)
			}
		}
	}
	if current != "" {
		// Bare number = seconds
		n, err := strconv.Atoi(current)
		if err != nil {
			return 0, fmt.Errorf("invalid duration: %s", s)
		}
		total += time.Duration(n) * time.Second
	}
	if total <= 0 {
		return 0, fmt.Errorf("duration must be positive")
	}
	return total, nil
}

func (o *OperServ) Shutdown() {
	if o.db != nil {
		_ = o.db.Close()
	}
	log.Printf("[%s] shutdown", o.Name())
}
