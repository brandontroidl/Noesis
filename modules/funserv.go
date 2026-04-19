// Copyright (c) Cathexis Development
// SPDX-License-Identifier: GPL-2.0-only
//
// modules/funserv.go — FunServ broker / bot directory.
//
// Rizon model (see /msg FunServ HELP): FunServ is NOT a monolithic fun bot.
// It's a thin broker that documents which per-channel bots the network runs
// and how channel founders request them. The actual commands go directly to
// each bot:
//
//     /msg Trivia    request #channel
//     /msg Quotes    request #channel
//     /msg LimitServ request #channel
//     /msg Internets request #channel
//     /msg eRepublik request #channel
//     /msg e-Sim     request #channel
//
// FunServ owns no commands of its own beyond HELP / INFO / STATUS.
//
// Historical note: pre-1.9.0 versions of this file implemented DICE/COIN/
// ROULETTE/SEEN/WEATHER/QUOTE/TRIVIA inline, duplicating what the individual
// bots already handle. That consolidated implementation was wrong for the
// Rizon topology; this file now matches Rizon FunServ's actual behavior.

package modules

import (
	"fmt"
	"log"
	"strings"

	"github.com/brandontroidl/noesis/ircv3"
	"github.com/brandontroidl/noesis/server"
)

// assignableBot describes one bot that channel founders can request.
type assignableBot struct {
	Nick        string
	Description string
	Available   bool // whether this bot is currently enabled on the network
}

type FunServ struct {
	pc   *server.PseudoClient
	bots []assignableBot
}

func NewFunServ() *FunServ  { return &FunServ{} }
func (f *FunServ) Name() string { return "funserv" }

func (f *FunServ) Init(s *server.Server) error {
	cfg := s.Config().Modules.FunServ
	if !cfg.Enabled {
		log.Printf("[%s] disabled", f.Name())
		return nil
	}
	nick := cfg.Nick
	if nick == "" {
		nick = "FunServ"
	}
	ident := cfg.Ident
	if ident == "" {
		ident = "funserv"
	}
	gecos := cfg.Gecos
	if gecos == "" {
		gecos = "Channel Fun Service Broker"
	}

	// Bot directory is derived from the other modules' enabled-state at Init
	// time, so operators don't maintain this list in two places.
	m := s.Config().Modules
	f.bots = []assignableBot{
		{Nick: "Trivia", Description: "A bot for trivia questions", Available: m.Trivia.Enabled},
		{Nick: "Quotes", Description: "A bot to store random channel quotes in", Available: m.Quotes.Enabled},
		{Nick: "LimitServ", Description: "A bot to keep a limit on the room to avoid floods", Available: m.LimitServ.Enabled},
		{Nick: "Internets", Description: "A bot that searches sites: Google, Bash, Qdb, UrbanDictionary, and FML", Available: m.Internets.Enabled},
		// eRepublik and e-Sim are Rizon-specific game bots not ported to
		// Brandon's acid; listed here for topology parity and marked
		// unavailable so FunServ HELP is honest about what's running.
		{Nick: "eRepublik", Description: "A bot for the popular MMORPG eRepublik", Available: false},
		{Nick: "e-Sim", Description: "A bot for eSim", Available: false},
	}

	pc, err := s.IntroducePseudoClient(nick, ident, s.Config().Server.Name, gecos, f)
	if err != nil {
		return fmt.Errorf("introduce %s: %w", nick, err)
	}
	f.pc = pc
	available := 0
	for _, b := range f.bots {
		if b.Available {
			available++
		}
	}
	log.Printf("[%s] initialized as %s (%d of %d bots available)", f.Name(), nick, available, len(f.bots))
	return nil
}

func (f *FunServ) HandleMessage(s *server.Server, msg *ircv3.P10Message) {
	if f.pc == nil || (msg.Command != "P" && msg.Command != "PRIVMSG") || len(msg.Params) < 2 {
		return
	}
	if !strings.EqualFold(msg.Params[0], f.pc.Nick) && !strings.EqualFold(msg.Params[0], f.pc.Numeric) {
		return
	}
	parts := strings.Fields(msg.Params[1])
	if len(parts) == 0 {
		return
	}
	target := msg.Source

	switch strings.ToUpper(parts[0]) {
	case "HELP", "INFO":
		f.sendHelp(s, target)
	case "STATUS":
		f.sendStatus(s, target)
	default:
		_ = s.SendNotice(f.pc.Numeric, target, "Unknown command. Use HELP.")
	}
}

func (f *FunServ) sendHelp(s *server.Server, target string) {
	send := func(line string) { _ = s.SendNotice(f.pc.Numeric, target, line) }
	send("All commands listed here are only available to channel founders.")
	send("Once the bot joined, use .help for more information on any one bot.")
	send(" ")
	for _, b := range f.bots {
		tag := ""
		if !b.Available {
			tag = " (unavailable on this network)"
		}
		send(fmt.Sprintf("\x02%s\x02: %s%s", b.Nick, b.Description, tag))
		send(fmt.Sprintf("To request: /msg %s request \x1f#channel\x1f", b.Nick))
		send(fmt.Sprintf("To remove:  /msg %s remove \x1f#channel\x1f", b.Nick))
		send(" ")
	}
}

func (f *FunServ) sendStatus(s *server.Server, target string) {
	send := func(line string) { _ = s.SendNotice(f.pc.Numeric, target, line) }
	send("\x02FunServ status\x02 — assignable bots on this network:")
	for _, b := range f.bots {
		state := "disabled"
		if b.Available {
			state = "available"
		}
		send(fmt.Sprintf("  %-10s %s", b.Nick, state))
	}
}

func (f *FunServ) Shutdown() {}
