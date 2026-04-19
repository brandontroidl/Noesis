// Copyright (c) Cathexis Development
// SPDX-License-Identifier: GPL-2.0-only
//
// modules/xmas.go — Seasonal event service.
//
// Provides holiday-themed interactions via a pseudo-client.
// Active during configurable seasonal periods.

package modules

import (
	"fmt"
	"log"
	"math/rand"
	"strings"

	"github.com/brandontroidl/noesis/ircv3"
	"github.com/brandontroidl/noesis/server"
)

// Xmas provides seasonal event features.
type Xmas struct {
	pc *server.PseudoClient
}

func NewXmas() *Xmas {
	return &Xmas{}
}

func (x *Xmas) Name() string { return "xmas" }

func (x *Xmas) Init(s *server.Server) error {
	cfg := s.Config().Modules.Xmas
	if !cfg.Enabled {
		log.Printf("[%s] disabled", x.Name())
		return nil
	}

	nick := cfg.Nick
	if nick == "" {
		nick = "XmasBot"
	}
	ident := cfg.Ident
	if ident == "" {
		ident = "xmas"
	}
	gecos := cfg.Gecos
	if gecos == "" {
		gecos = "Seasonal Events"
	}

	pc, err := s.IntroducePseudoClient(nick, ident, s.Config().Server.Name, gecos, x)
	if err != nil {
		return fmt.Errorf("introduce %s: %w", nick, err)
	}
	x.pc = pc

	log.Printf("[%s] initialized as %s (%s)", x.Name(), nick, pc.Numeric)
	return nil
}

func (x *Xmas) HandleMessage(s *server.Server, msg *ircv3.P10Message) {
	if x.pc == nil {
		return
	}

	text := msg.Trailing()
	prefix := s.Config().Services.Prefix
	target := msg.Param(0)

	if text == prefix+"gift" {
		gifts := []string{
			"a mass of coal",
			"a candy cane",
			"a warm cup of cocoa",
			"a tiny snowman figurine",
			"a pair of fuzzy socks",
			"a gingerbread cookie",
			"an ugly holiday sweater",
		}
		nick := msg.Source
		if u := s.Network().GetUser(msg.Source); u != nil {
			nick = u.Nick
		}
		gift := gifts[rand.Intn(len(gifts))]
		s.SendPrivmsg(x.pc.Numeric, target,
			fmt.Sprintf("gives %s %s!", nick, gift))

	} else if strings.HasPrefix(text, prefix+"countdown") {
		s.SendPrivmsg(x.pc.Numeric, target, "The holiday season is always in our hearts!")
	}
}

func (x *Xmas) Shutdown() {
	log.Printf("[%s] shutdown", x.Name())
}
