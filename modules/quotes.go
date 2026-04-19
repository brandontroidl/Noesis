// Copyright (c) Cathexis Development
// SPDX-License-Identifier: GPL-2.0-only
//
// modules/quotes.go — Quote storage and retrieval service.

package modules

import (
	"fmt"
	"log"
	"strconv"
	"strings"

	"github.com/brandontroidl/noesis/ircv3"
	"github.com/brandontroidl/noesis/server"
	"github.com/brandontroidl/noesis/store"
)

// Quotes provides quote storage and retrieval.
type Quotes struct {
	pc    *server.PseudoClient
	store *store.QuoteStore
}

func NewQuotes() *Quotes {
	return &Quotes{}
}

func (q *Quotes) Name() string { return "quotes" }

func (q *Quotes) Init(s *server.Server) error {
	cfg := s.Config().Modules.Quotes
	if !cfg.Enabled {
		log.Printf("[%s] disabled", q.Name())
		return nil
	}

	q.store = s.Quotes()

	nick := cfg.Nick
	if nick == "" {
		nick = "QuoteBot"
	}
	ident := cfg.Ident
	if ident == "" {
		ident = "quotes"
	}
	gecos := cfg.Gecos
	if gecos == "" {
		gecos = "Quote Service"
	}

	pc, err := s.IntroducePseudoClient(nick, ident, s.Config().Server.Name, gecos, q)
	if err != nil {
		return fmt.Errorf("introduce %s: %w", nick, err)
	}
	q.pc = pc

	log.Printf("[%s] initialized as %s (%s) with %d quotes",
		q.Name(), nick, pc.Numeric, q.store.Count())
	return nil
}

func (q *Quotes) HandleMessage(s *server.Server, msg *ircv3.P10Message) {
	if q.pc == nil {
		return
	}

	text := msg.Trailing()
	prefix := s.Config().Services.Prefix
	target := msg.Param(0)

	// DM help
	isDM := len(target) == 0 || (target[0] != '#' && target[0] != '&' && target[0] != '+' && target[0] != '!')
	if isDM {
		fields := strings.Fields(text)
		if len(fields) == 0 { return }
		cmd := strings.ToUpper(strings.TrimLeft(fields[0], "!."))
		if cmd == "HELP" {
			_ = s.SendNotice(q.pc.Numeric, msg.Source, "\x02Quotes — Channel Quote Database\x02")
			_ = s.SendNotice(q.pc.Numeric, msg.Source, fmt.Sprintf("  %squote add <text>     — Add a quote", prefix))
			_ = s.SendNotice(q.pc.Numeric, msg.Source, fmt.Sprintf("  %squote del <#>        — Delete a quote (helper+)", prefix))
			_ = s.SendNotice(q.pc.Numeric, msg.Source, fmt.Sprintf("  %squote search <term>  — Search quotes", prefix))
			_ = s.SendNotice(q.pc.Numeric, msg.Source, fmt.Sprintf("  %squote read <#>       — Read a specific quote", prefix))
			_ = s.SendNotice(q.pc.Numeric, msg.Source, fmt.Sprintf("  %squote                — Random quote", prefix))
			_ = s.SendNotice(q.pc.Numeric, msg.Source, fmt.Sprintf("  %squote stats          — Quote database stats", prefix))
			return
		}
		return
	}

	switch {
	case strings.HasPrefix(text, prefix+"quote add "):
		quoteText := strings.TrimPrefix(text, prefix+"quote add ")
		nick := msg.Source
		if u := s.Network().GetUser(msg.Source); u != nil {
			nick = u.Nick
		}
		id := q.store.Add(quoteText, nick, target)
		s.SendPrivmsg(q.pc.Numeric, target, fmt.Sprintf("Quote #%d added.", id))

	case strings.HasPrefix(text, prefix+"quote del "):
		// Require helper+ to delete
		if !s.RequirePrivilege(msg.Source, target, q.pc.Numeric, server.PrivHelper) {
			return
		}
		idStr := strings.TrimPrefix(text, prefix+"quote del ")
		id, err := strconv.Atoi(strings.TrimSpace(idStr))
		if err != nil {
			s.SendPrivmsg(q.pc.Numeric, target, "Usage: "+prefix+"quote del <number>")
			return
		}
		if q.store.Delete(id) {
			s.SendPrivmsg(q.pc.Numeric, target, fmt.Sprintf("Quote #%d deleted.", id))
		} else {
			s.SendPrivmsg(q.pc.Numeric, target, fmt.Sprintf("Quote #%d not found.", id))
		}

	case strings.HasPrefix(text, prefix+"quote search "):
		term := strings.TrimPrefix(text, prefix+"quote search ")
		results := q.store.Search(strings.TrimSpace(term))
		if len(results) == 0 {
			s.SendPrivmsg(q.pc.Numeric, target, "No quotes found.")
		} else {
			shown := results
			if len(shown) > 5 {
				shown = shown[:5]
			}
			for _, qe := range shown {
				s.SendPrivmsg(q.pc.Numeric, target,
					fmt.Sprintf("[#%d] %s (by %s)", qe.ID, qe.Text, qe.AddedBy))
			}
			if len(results) > 5 {
				s.SendPrivmsg(q.pc.Numeric, target,
					fmt.Sprintf("...and %d more.", len(results)-5))
			}
		}

	case strings.HasPrefix(text, prefix+"quote #"):
		idStr := strings.TrimPrefix(text, prefix+"quote #")
		id, err := strconv.Atoi(strings.TrimSpace(idStr))
		if err != nil {
			return
		}
		qe := q.store.Get(id)
		if qe == nil {
			s.SendPrivmsg(q.pc.Numeric, target, fmt.Sprintf("Quote #%d not found.", id))
		} else {
			s.SendPrivmsg(q.pc.Numeric, target,
				fmt.Sprintf("[#%d] %s (by %s)", qe.ID, qe.Text, qe.AddedBy))
		}

	case text == prefix+"quote" || text == prefix+"quote random":
		qe := q.store.Random()
		if qe == nil {
			s.SendPrivmsg(q.pc.Numeric, target, "No quotes stored yet.")
		} else {
			s.SendPrivmsg(q.pc.Numeric, target,
				fmt.Sprintf("[#%d] %s (by %s)", qe.ID, qe.Text, qe.AddedBy))
		}

	case text == prefix+"quote count":
		s.SendPrivmsg(q.pc.Numeric, target,
			fmt.Sprintf("%d quotes stored.", q.store.Count()))
	}
}

func (q *Quotes) Shutdown() {
	log.Printf("[%s] shutdown", q.Name())
}
