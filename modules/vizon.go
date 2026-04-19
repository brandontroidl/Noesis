// Copyright (c) Cathexis Development
// SPDX-License-Identifier: GPL-2.0-only
//
// modules/vizon.go — Network visibility and monitoring service.
//
// Provides network statistics, user lookups, and monitoring
// capabilities via a pseudo-client.

package modules

import (
	"fmt"
	"log"
	"strings"

	"github.com/brandontroidl/noesis/ircv3"
	"github.com/brandontroidl/noesis/server"
)

// Vizon provides network visibility and monitoring.
type Vizon struct {
	pc *server.PseudoClient
}

func NewVizon() *Vizon {
	return &Vizon{}
}

func (v *Vizon) Name() string { return "vizon" }

func (v *Vizon) Init(s *server.Server) error {
	cfg := s.Config().Modules.Vizon
	if !cfg.Enabled {
		log.Printf("[%s] disabled", v.Name())
		return nil
	}

	nick := cfg.Nick
	if nick == "" {
		nick = "Vizon"
	}
	ident := cfg.Ident
	if ident == "" {
		ident = "vizon"
	}
	gecos := cfg.Gecos
	if gecos == "" {
		gecos = "Network Monitor"
	}

	pc, err := s.IntroducePseudoClient(nick, ident, s.Config().Server.Name, gecos, v)
	if err != nil {
		return fmt.Errorf("introduce %s: %w", nick, err)
	}
	v.pc = pc

	log.Printf("[%s] initialized as %s (%s)", v.Name(), nick, pc.Numeric)
	return nil
}

func (v *Vizon) HandleMessage(s *server.Server, msg *ircv3.P10Message) {
	if v.pc == nil {
		return
	}

	text := msg.Trailing()
	prefix := s.Config().Services.Prefix
	target := msg.Param(0)

	// DM commands
	isDM := len(target) == 0 || (target[0] != '#' && target[0] != '&')
	if isDM {
		cmd := strings.ToUpper(strings.TrimSpace(strings.TrimLeft(strings.Fields(text)[0], "!.")))
		if cmd == "HELP" {
			_ = s.SendNotice(v.pc.Numeric, msg.Source, "\x02V — Network Monitor\x02")
			_ = s.SendNotice(v.pc.Numeric, msg.Source, fmt.Sprintf("  %sstats          — Network statistics", prefix))
			_ = s.SendNotice(v.pc.Numeric, msg.Source, fmt.Sprintf("  %sfind <nick>    — User lookup", prefix))
			_ = s.SendNotice(v.pc.Numeric, msg.Source, fmt.Sprintf("  %scinfo <#chan>  — Channel info", prefix))
			_ = s.SendNotice(v.pc.Numeric, msg.Source, "Commands work in channels with the prefix.")
		}
		return
	}

	switch {
	case text == prefix+"stats":
		net := s.Network()
		stats := fmt.Sprintf("Network: %d users, %d channels, %d servers",
			net.UserCount(), net.ChannelCount(), net.ServerCount())
		if ms := s.Messages(); ms != nil {
			stats += fmt.Sprintf(" | History: %d messages across %d targets",
				ms.MessageCount(), ms.TargetCount())
		}
		if qs := s.Quotes(); qs != nil {
			stats += fmt.Sprintf(" | Quotes: %d", qs.Count())
		}
		s.SendPrivmsg(v.pc.Numeric, target, stats)

	case strings.HasPrefix(text, prefix+"find "):
		nick := strings.TrimPrefix(text, prefix+"find ")
		nick = strings.TrimSpace(nick)
		u := s.Network().FindUserByNick(nick)
		if u == nil {
			s.SendPrivmsg(v.pc.Numeric, target, fmt.Sprintf("User %s not found.", nick))
		} else {
			acct := u.Account
			if acct == "" {
				acct = "(not logged in)"
			}
			s.SendPrivmsg(v.pc.Numeric, target,
				fmt.Sprintf("%s (%s@%s) [%s] account: %s",
					u.Nick, u.Ident, u.Host, u.Gecos, acct))
		}

	case strings.HasPrefix(text, prefix+"cinfo "):
		chName := strings.TrimPrefix(text, prefix+"cinfo ")
		chName = strings.TrimSpace(chName)
		ch := s.Network().GetChannel(chName)
		if ch == nil {
			s.SendPrivmsg(v.pc.Numeric, target, fmt.Sprintf("Channel %s not found.", chName))
		} else {
			s.SendPrivmsg(v.pc.Numeric, target,
				fmt.Sprintf("%s: %d members, modes: %s, topic: %s",
					ch.Name, len(ch.Members), ch.Modes, ch.Topic))
		}
	}
}

func (v *Vizon) Shutdown() {
	log.Printf("[%s] shutdown", v.Name())
}
