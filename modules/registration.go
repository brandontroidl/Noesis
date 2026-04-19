// Copyright (c) Cathexis Development
// SPDX-License-Identifier: GPL-2.0-only
//
// modules/registration.go — Channel registration greeter.
//
// Ported from Rizon acid's pyva/registration/registration.py. Watches for
// ChanServ setting +z on a newly-registered channel, then posts configurable
// welcome/info lines to that channel as a dedicated pseudo-client.

package modules

import (
	"fmt"
	"log"
	"strings"

	"github.com/brandontroidl/noesis/ircv3"
	"github.com/brandontroidl/noesis/server"
)

type Registration struct {
	pc    *server.PseudoClient
	text  []string
	logCh string
}

func NewRegistration() *Registration { return &Registration{} }
func (r *Registration) Name() string { return "registration" }

func (r *Registration) Init(s *server.Server) error {
	cfg := s.Config().Modules.Registration
	if !cfg.Enabled {
		log.Printf("[%s] disabled", r.Name())
		return nil
	}
	nick := cfg.Nick
	if nick == "" {
		nick = "Registrar"
	}
	ident := cfg.Ident
	if ident == "" {
		ident = "registrar"
	}
	gecos := cfg.Gecos
	if gecos == "" {
		gecos = "Channel Registration Greeter"
	}
	r.text = cfg.WelcomeLines
	if len(r.text) == 0 {
		r.text = []string{
			"Your channel has been registered. Type /msg ChanServ HELP for commands.",
			"For help with network features, type /msg Global HELP.",
		}
	}
	r.logCh = cfg.LogChannel

	pc, err := s.IntroducePseudoClient(nick, ident, s.Config().Server.Name, gecos, r)
	if err != nil {
		return fmt.Errorf("introduce %s: %w", nick, err)
	}
	r.pc = pc
	log.Printf("[%s] initialized as %s", r.Name(), nick)
	return nil
}

func (r *Registration) HandleMessage(s *server.Server, msg *ircv3.P10Message) {
	if r.pc == nil {
		return
	}
	// Only interested in MODE messages
	if msg.Command != "M" && msg.Command != "MODE" {
		return
	}
	// P10 MODE: source M target modes [args...]
	if len(msg.Params) < 2 {
		return
	}
	target := msg.Params[0]
	if !strings.HasPrefix(target, "#") && !strings.HasPrefix(target, "&") {
		return // not a channel mode
	}
	modes := msg.Params[1]
	// Rizon's registration.py: "we only want +z for starts"
	if modes != "+z" {
		return
	}
	// Verify the source is ChanServ (not any random oper setting +z)
	srcUser := s.Network().GetUser(msg.Source)
	if srcUser == nil || !strings.EqualFold(srcUser.Nick, "ChanServ") {
		return
	}

	log.Printf("[registration] channel %s registered — sending greeting", target)
	for _, line := range r.text {
		_ = s.SendPrivmsg(r.pc.Numeric, target, line)
	}

	if r.logCh != "" {
		_ = s.SendPrivmsg(r.pc.Numeric, r.logCh, fmt.Sprintf("registration info sent to %s", target))
	}
}

func (r *Registration) Shutdown() {}
