// Copyright (c) Cathexis Development
// SPDX-License-Identifier: GPL-2.0-only
//
// modules/limitserv.go — Channel limit enforcement service.
//
// Monitors channel membership counts and adjusts +l limits with
// a configurable padding to prevent join floods.

package modules

import (
	"fmt"
	"log"
	"time"

	"github.com/brandontroidl/noesis/ircv3"
	"github.com/brandontroidl/noesis/server"
)

// LimitServ enforces dynamic channel limits.
type LimitServ struct {
	pc       *server.PseudoClient
	padding  int
	interval int
	stopCh   chan struct{}
}

func NewLimitServ() *LimitServ {
	return &LimitServ{
		stopCh: make(chan struct{}),
	}
}

func (l *LimitServ) Name() string { return "limitserv" }

func (l *LimitServ) Init(s *server.Server) error {
	cfg := s.Config().Modules.LimitServ
	if !cfg.Enabled {
		log.Printf("[%s] disabled", l.Name())
		return nil
	}

	l.padding = cfg.Padding
	if l.padding <= 0 {
		l.padding = 5
	}
	l.interval = cfg.Interval
	if l.interval <= 0 {
		l.interval = 60
	}

	nick := cfg.Nick
	if nick == "" {
		nick = "LimitServ"
	}
	ident := cfg.Ident
	if ident == "" {
		ident = "limitserv"
	}
	gecos := cfg.Gecos
	if gecos == "" {
		gecos = "Channel Limit Service"
	}

	pc, err := s.IntroducePseudoClient(nick, ident, s.Config().Server.Name, gecos, l)
	if err != nil {
		return fmt.Errorf("introduce %s: %w", nick, err)
	}
	l.pc = pc

	// Start limit enforcement ticker
	go l.enforceLimits(s)

	log.Printf("[%s] initialized as %s (%s) padding=%d interval=%ds",
		l.Name(), nick, pc.Numeric, l.padding, l.interval)
	return nil
}

func (l *LimitServ) HandleMessage(s *server.Server, msg *ircv3.P10Message) {
	// LimitServ uses hooks and the ticker, not direct PRIVMSG commands
}

// RegisterHooks registers LimitServ for membership change events.
func (l *LimitServ) RegisterHooks(hm *server.HookManager) {
	// Track channel membership changes to trigger limit recalculation
	recalc := func(s *server.Server, msg *ircv3.P10Message) {
		// The ticker handles periodic updates; hooks just ensure
		// we don't miss rapid changes. No-op for now since the
		// ticker loop handles everything.
	}
	hm.Register(server.EventJoin, recalc)
	hm.Register(server.EventPart, recalc)
	hm.Register(server.EventQuit, recalc)
	hm.Register(server.EventKick, recalc)
}

func (l *LimitServ) enforceLimits(s *server.Server) {
	ticker := time.NewTicker(time.Duration(l.interval) * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-l.stopCh:
			return
		case <-ticker.C:
			l.adjustLimits(s)
		}
	}
}

func (l *LimitServ) adjustLimits(s *server.Server) {
	if l.pc == nil {
		return
	}

	net := s.Network()
	// Iterate all channels and adjust +l where we have ops
	for _, chName := range net.ChannelNames() {
		ch := net.GetChannel(chName)
		if ch == nil {
			continue
		}
		members := net.ChannelMemberCount(chName)
		if members == 0 {
			continue
		}
		desiredLimit := members + l.padding
		if ch.Limit != desiredLimit {
			// Set +l via OPMODE (server-level mode change)
			_ = s.SendP10(&ircv3.P10Message{
				Source:  s.ServerNumeric(),
				Command: "OM", // OPMODE token
				Params:  []string{chName, "+l", fmt.Sprintf("%d", desiredLimit)},
			})
		}
	}
}

func (l *LimitServ) Shutdown() {
	close(l.stopCh)
	log.Printf("[%s] shutdown", l.Name())
}
