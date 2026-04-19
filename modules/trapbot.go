// Copyright (c) Cathexis Development
// SPDX-License-Identifier: GPL-2.0-only
//
// modules/trapbot.go — Honeypot channel monitoring service.
//
// Monitors configured trap channels and applies configured actions
// (GLINE, KLINE, KILL) to any user who joins them.

package modules

import (
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/brandontroidl/noesis/ircv3"
	"github.com/brandontroidl/noesis/server"
)

// TrapBot monitors honeypot channels.
type TrapBot struct {
	pc       *server.PseudoClient
	channels map[string]bool
	action   string
	duration int
	reason   string
	recent   map[string]time.Time // dedup: "numeric:channel" → last action time
}

func NewTrapBot() *TrapBot {
	return &TrapBot{
		channels: make(map[string]bool),
		recent:   make(map[string]time.Time),
	}
}

func (t *TrapBot) Name() string { return "trapbot" }

func (t *TrapBot) Init(s *server.Server) error {
	cfg := s.Config().Modules.TrapBot
	if !cfg.Enabled {
		log.Printf("[%s] disabled", t.Name())
		return nil
	}

	t.action = strings.ToLower(cfg.Action)
	if t.action == "" {
		t.action = "gline"
	}
	t.duration = cfg.Duration
	if t.duration <= 0 {
		t.duration = 3600
	}
	t.reason = cfg.Reason
	if t.reason == "" {
		t.reason = "Honeypot channel join detected"
	}

	for _, ch := range cfg.Channels {
		t.channels[strings.ToLower(ch)] = true
	}

	nick := cfg.Nick
	if nick == "" {
		nick = "TrapBot"
	}
	ident := cfg.Ident
	if ident == "" {
		ident = "trap"
	}
	gecos := cfg.Gecos
	if gecos == "" {
		gecos = "Trap Channel Monitor"
	}

	pc, err := s.IntroducePseudoClient(nick, ident, s.Config().Server.Name, gecos, t)
	if err != nil {
		return fmt.Errorf("introduce %s: %w", nick, err)
	}
	t.pc = pc

	// Join trap channels
	for ch := range t.channels {
		_ = s.JoinPseudoClient(pc.Numeric, ch)
	}

	log.Printf("[%s] initialized as %s (%s) monitoring %d channels action=%s",
		t.Name(), nick, pc.Numeric, len(t.channels), t.action)
	return nil
}

func (t *TrapBot) HandleMessage(s *server.Server, msg *ircv3.P10Message) {
	// TrapBot uses hooks for JOIN detection, not PRIVMSG
}

// RegisterHooks registers TrapBot for JOIN events.
func (t *TrapBot) RegisterHooks(hm *server.HookManager) {
	hm.Register(server.EventJoin, func(s *server.Server, msg *ircv3.P10Message) {
		if t.pc == nil {
			return
		}
		if len(msg.Params) < 1 {
			return
		}
		channels := strings.Split(msg.Param(0), ",")
		for _, ch := range channels {
			t.OnJoin(s, msg.Source, ch)
		}
	})
}

// OnJoin is called when a user joins a trap channel.
// Wire this from server.go handleJoinMessage.
func (t *TrapBot) OnJoin(s *server.Server, numeric, channel string) {
	if t.pc == nil {
		return
	}

	if !t.channels[strings.ToLower(channel)] {
		return
	}

	// Dedup: don't act on the same user+channel within 30 seconds
	key := numeric + ":" + strings.ToLower(channel)
	if last, ok := t.recent[key]; ok && time.Since(last) < 30*time.Second {
		return
	}
	t.recent[key] = time.Now()

	// Don't trap our own pseudo-clients
	if numeric == t.pc.Numeric {
		return
	}

	u := s.Network().GetUser(numeric)
	if u == nil {
		return
	}

	// Don't trap IRC operators
	if u.IsOper() {
		log.Printf("[%s] exempted oper %s from trap in %s", t.Name(), u.Nick, channel)
		return
	}

	log.Printf("[%s] trapped %s (%s@%s) in %s", t.Name(), u.Nick, u.Ident, u.Host, channel)

	switch t.action {
	case "gline":
		mask := fmt.Sprintf("*@%s", u.Host)
		now := fmt.Sprintf("%d", time.Now().Unix())
		lifetime := fmt.Sprintf("%d", t.duration*2) // lifetime = 2x duration
		_ = s.SendP10(&ircv3.P10Message{
			Source:  s.ServerNumeric(),
			Command: "GL",
			Params:  []string{"*", "+" + mask, fmt.Sprintf("%d", t.duration), now, lifetime, t.reason},
		})
	case "kill":
		_ = s.SendP10(&ircv3.P10Message{
			Source:  t.pc.Numeric,
			Command: "D",
			Params:  []string{numeric, t.reason},
		})
	}
}

func (t *TrapBot) Shutdown() {
	log.Printf("[%s] shutdown", t.Name())
}
