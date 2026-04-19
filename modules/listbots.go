// Copyright (c) Cathexis Development
// SPDX-License-Identifier: GPL-2.0-only
//
// modules/listbots.go — Pseudo-client directory service.
//
// Ported from Rizon acid's pyva/listbots/listbots.py. Maintains a list of
// network pseudo-clients (services bots) with descriptions. Admins can add,
// remove, and rename entries; users can list them.

package modules

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"sort"
	"strings"
	"sync"

	"github.com/brandontroidl/noesis/ircv3"
	"github.com/brandontroidl/noesis/server"
)

type ListBots struct {
	pc      *server.PseudoClient
	store   string
	mu      sync.RWMutex
	entries map[string]string // nick → description
}

func NewListBots() *ListBots { return &ListBots{entries: make(map[string]string)} }
func (l *ListBots) Name() string { return "listbots" }

func (l *ListBots) Init(s *server.Server) error {
	cfg := s.Config().Modules.ListBots
	if !cfg.Enabled {
		log.Printf("[%s] disabled", l.Name())
		return nil
	}
	nick := cfg.Nick
	if nick == "" {
		nick = "ListBots"
	}
	ident := cfg.Ident
	if ident == "" {
		ident = "listbots"
	}
	gecos := cfg.Gecos
	if gecos == "" {
		gecos = "Network Bot Directory"
	}
	l.store = cfg.DataFile
	if l.store == "" {
		l.store = "data/listbots.json"
	}
	l.load()

	pc, err := s.IntroducePseudoClient(nick, ident, s.Config().Server.Name, gecos, l)
	if err != nil {
		return fmt.Errorf("introduce %s: %w", nick, err)
	}
	l.pc = pc
	log.Printf("[%s] initialized as %s (%d entries)", l.Name(), nick, len(l.entries))
	return nil
}

func (l *ListBots) HandleMessage(s *server.Server, msg *ircv3.P10Message) {
	if l.pc == nil || (msg.Command != "P" && msg.Command != "PRIVMSG") || len(msg.Params) < 2 {
		return
	}
	if !strings.EqualFold(msg.Params[0], l.pc.Nick) && !strings.EqualFold(msg.Params[0], l.pc.Numeric) {
		return
	}
	parts := strings.Fields(msg.Params[1])
	if len(parts) == 0 {
		return
	}
	target := msg.Source
	cmd := strings.ToUpper(parts[0])

	switch cmd {
	case "HELP":
		for _, line := range []string{
			"ListBots commands:",
			"  LIST                       — List all registered bots",
			"  ADD <nick> <description>   — Register a bot (admin)",
			"  DEL <nick>                 — Remove a bot (admin)",
			"  INFO <nick>                — Show description for one bot",
		} {
			_ = s.SendNotice(l.pc.Numeric, target, line)
		}

	case "LIST":
		l.mu.RLock()
		defer l.mu.RUnlock()
		if len(l.entries) == 0 {
			_ = s.SendNotice(l.pc.Numeric, target, "No bots registered.")
			return
		}
		nicks := make([]string, 0, len(l.entries))
		for n := range l.entries {
			nicks = append(nicks, n)
		}
		sort.Strings(nicks)
		_ = s.SendNotice(l.pc.Numeric, target, fmt.Sprintf("Registered network bots (%d):", len(nicks)))
		for _, n := range nicks {
			_ = s.SendNotice(l.pc.Numeric, target, fmt.Sprintf("  \x02%s\x02 — %s", n, l.entries[n]))
		}

	case "INFO":
		if len(parts) < 2 {
			_ = s.SendNotice(l.pc.Numeric, target, "Usage: INFO <nick>")
			return
		}
		l.mu.RLock()
		desc, ok := l.entries[strings.ToLower(parts[1])]
		l.mu.RUnlock()
		if !ok {
			_ = s.SendNotice(l.pc.Numeric, target, fmt.Sprintf("No entry for %s.", parts[1]))
			return
		}
		_ = s.SendNotice(l.pc.Numeric, target, fmt.Sprintf("\x02%s\x02: %s", parts[1], desc))

	case "ADD":
		u := s.Network().GetUser(msg.Source)
		if u == nil || !u.IsOper() {
			_ = s.SendNotice(l.pc.Numeric, target, "Permission denied.")
			return
		}
		if len(parts) < 3 {
			_ = s.SendNotice(l.pc.Numeric, target, "Usage: ADD <nick> <description>")
			return
		}
		nick := strings.ToLower(parts[1])
		desc := strings.Join(parts[2:], " ")
		l.mu.Lock()
		l.entries[nick] = desc
		l.mu.Unlock()
		l.save()
		_ = s.SendNotice(l.pc.Numeric, target, fmt.Sprintf("Added %s (%s).", parts[1], desc))

	case "DEL", "DELETE", "REMOVE":
		u := s.Network().GetUser(msg.Source)
		if u == nil || !u.IsOper() {
			_ = s.SendNotice(l.pc.Numeric, target, "Permission denied.")
			return
		}
		if len(parts) < 2 {
			_ = s.SendNotice(l.pc.Numeric, target, "Usage: DEL <nick>")
			return
		}
		nick := strings.ToLower(parts[1])
		l.mu.Lock()
		_, ok := l.entries[nick]
		delete(l.entries, nick)
		l.mu.Unlock()
		if !ok {
			_ = s.SendNotice(l.pc.Numeric, target, fmt.Sprintf("No entry for %s.", parts[1]))
			return
		}
		l.save()
		_ = s.SendNotice(l.pc.Numeric, target, fmt.Sprintf("Removed %s.", parts[1]))

	default:
		_ = s.SendNotice(l.pc.Numeric, target, "Unknown command. Use HELP.")
	}
}

func (l *ListBots) Shutdown() {}

func (l *ListBots) load() {
	data, err := os.ReadFile(l.store)
	if err != nil {
		return
	}
	var m map[string]string
	if err := json.Unmarshal(data, &m); err != nil {
		log.Printf("[listbots] failed to parse %s: %v", l.store, err)
		return
	}
	l.mu.Lock()
	l.entries = m
	l.mu.Unlock()
}

func (l *ListBots) save() {
	l.mu.RLock()
	data, err := json.MarshalIndent(l.entries, "", "  ")
	l.mu.RUnlock()
	if err != nil {
		log.Printf("[listbots] marshal error: %v", err)
		return
	}
	tmp := l.store + ".tmp"
	if err := os.WriteFile(tmp, data, 0644); err != nil {
		log.Printf("[listbots] write error: %v", err)
		return
	}
	_ = os.Rename(tmp, l.store)
}
