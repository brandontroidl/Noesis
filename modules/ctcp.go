// Copyright (c) Cathexis Development
// SPDX-License-Identifier: GPL-2.0-only
//
// modules/ctcp.go — CTCP response handler for pseudo-clients.
//
// Responds to CTCP VERSION, PING, and TIME queries directed at
// any Acid pseudo-client.

package modules

import (
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/brandontroidl/noesis/ircv3"
	"github.com/brandontroidl/noesis/server"
)

// CTCP handles CTCP responses for all pseudo-clients.
type CTCP struct {
	versionReply string
}

func NewCTCP() *CTCP {
	return &CTCP{}
}

func (c *CTCP) Name() string { return "ctcp" }

func (c *CTCP) Init(s *server.Server) error {
	cfg := s.Config().Modules.CTCP
	if !cfg.Enabled {
		log.Printf("[%s] disabled", c.Name())
		return nil
	}

	c.versionReply = cfg.VersionReply
	if c.versionReply == "" {
		c.versionReply = "noesis 1.0.1 - Cathexis P10 Services Framework"
	}

	log.Printf("[%s] initialized", c.Name())
	return nil
}

func (c *CTCP) HandleMessage(s *server.Server, msg *ircv3.P10Message) {
	text := msg.Trailing()
	if len(text) < 2 || text[0] != '\x01' {
		return
	}

	// Strip CTCP delimiters
	ctcp := strings.TrimRight(text[1:], "\x01")
	parts := strings.SplitN(ctcp, " ", 2)
	command := strings.ToUpper(parts[0])

	target := msg.Param(0)

	switch command {
	case "VERSION":
		s.SendNotice(target, msg.Source,
			fmt.Sprintf("\x01VERSION %s\x01", c.versionReply))

	case "PING":
		// Echo back the ping payload
		payload := ""
		if len(parts) > 1 {
			payload = " " + parts[1]
		}
		s.SendNotice(target, msg.Source,
			fmt.Sprintf("\x01PING%s\x01", payload))

	case "TIME":
		s.SendNotice(target, msg.Source,
			fmt.Sprintf("\x01TIME %s\x01", time.Now().UTC().Format(time.RFC1123)))
	}
}

func (c *CTCP) Shutdown() {
	log.Printf("[%s] shutdown", c.Name())
}
