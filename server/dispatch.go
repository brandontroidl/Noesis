// Copyright (c) Cathexis Development
// SPDX-License-Identifier: GPL-2.0-only
//
// server/dispatch.go — Tag-aware P10 message dispatch.
//
// This file provides the IRCv3-aware message handling layer that
// sits between the raw TCP reader and the command handlers.
//
// INTEGRATION INSTRUCTIONS:
// In server.go, replace the raw line parsing in the message loop with:
//
//   OLD (current Acid code):
//     parts := strings.SplitN(line, " ", ...)
//     source := parts[0]
//     command := parts[1]
//     ...handler(source, command, params)
//
//   NEW:
//     msg := ircv3.ParseP10Line(line)
//     s.dispatchMessage(msg)
//
// This preserves all existing handler logic but adds tag awareness.

package server

import (
	"fmt"
	"log"
	"time"

	"github.com/brandontroidl/noesis/ircv3"
	"github.com/brandontroidl/noesis/p10"
)

// MessageHandler is the signature for tag-aware P10 command handlers.
type MessageHandler func(s *Server, msg *ircv3.P10Message)

// dispatchMessage routes a parsed P10Message to the appropriate handler.
// This replaces the raw string-based dispatch in handleLine().
func (s *Server) dispatchMessage(msg *ircv3.P10Message) {
	if msg.Command == "" {
		return
	}

	// Track batch state
	s.handleBatchTracking(msg)

	// Check if message is inside a batch we should skip
	if s.shouldSkipBatchMessage(msg) {
		return
	}

	// Route to handler
	handler, ok := s.msgHandlers[msg.Command]
	if ok {
		handler(s, msg)
		return
	}

	// Also check by full command name (P10 uses tokens like P for PRIVMSG)
	handler, ok = s.msgHandlers[tokenToCommand(msg.Command)]
	if ok {
		handler(s, msg)
		return
	}

	// Unknown command — log at debug level
	if s.config.Debug {
		log.Printf("[DEBUG] unhandled P10 command: %s (source: %s)", msg.Command, msg.Source)
	}
}

// handleBatchTracking processes BATCH start/end messages.
func (s *Server) handleBatchTracking(msg *ircv3.P10Message) {
	// BA is the P10 token for BATCH
	if msg.Command != "BA" && msg.Command != "BATCH" {
		return
	}
	if len(msg.Params) < 1 {
		return
	}

	ref := msg.Params[0]
	if len(ref) < 2 {
		return
	}

	switch ref[0] {
	case '+':
		// BATCH start
		refID := ref[1:]
		batchType := ""
		if len(msg.Params) > 1 {
			batchType = msg.Params[1]
		}
		var params []string
		if len(msg.Params) > 2 {
			params = msg.Params[2:]
		}
		s.batches.Start(refID, batchType, params)
		if s.config.Debug {
			log.Printf("[BATCH] started: %s type=%s", refID, batchType)
		}

	case '-':
		// BATCH end
		refID := ref[1:]
		b := s.batches.End(refID)
		if s.config.Debug && b != nil {
			log.Printf("[BATCH] ended: %s type=%s", refID, b.Type)
		}
	}
}

// shouldSkipBatchMessage returns true if the message is inside a
// batch type that Acid should not process (e.g., netsplit replay).
func (s *Server) shouldSkipBatchMessage(msg *ircv3.P10Message) bool {
	batch, inBatch := s.batches.IsInBatch(msg.Tags)
	if !inBatch {
		return false
	}

	// Skip messages inside netsplit/netjoin batches — these are
	// replayed state changes, not new user actions.
	switch batch.Type {
	case ircv3.BatchNetsplit, ircv3.BatchNetjoin:
		return true
	}

	return false
}

// SendP10 sends a raw P10 line to Cathexis.
// Note: IRCv3 tags are NOT injected on S2S lines — the ircd's P10 parser
// does not process them. Tags like server-time and msgid are added by the
// ircd when relaying to clients.
func (s *Server) SendP10(msg *ircv3.P10Message) error {
	// Clear any tags — S2S P10 is bare protocol only
	msg.Tags = nil

	line := msg.BuildP10Line()
	return s.sendRawLine(line)
}

// SendPrivmsg sends a PRIVMSG from a pseudo-client with full IRCv3 tags.
func (s *Server) SendPrivmsg(sourceNumeric, target, text string) error {
	msg := &ircv3.P10Message{
		Source:  sourceNumeric,
		Command: "P", // PRIVMSG token in P10
		Params:  []string{target, text},
	}
	return s.SendP10(msg)
}

// SendNotice sends a NOTICE from a pseudo-client with full IRCv3 tags.
func (s *Server) SendNotice(sourceNumeric, target, text string) error {
	msg := &ircv3.P10Message{
		Source:  sourceNumeric,
		Command: "O", // NOTICE token in P10
		Params:  []string{target, text},
	}
	return s.SendP10(msg)
}

// SendTagmsg sends a TAGMSG from a pseudo-client (tags only, no text body).
func (s *Server) SendTagmsg(sourceNumeric, target string, tags *ircv3.Tags) error {
	msg := &ircv3.P10Message{
		Tags:    tags,
		Source:  sourceNumeric,
		Command: "TG", // TAGMSG token in P10 (if Cathexis defines one)
		Params:  []string{target},
	}
	return s.SendP10(msg)
}

// SendBatchStart sends a BATCH +refid type [params] line.
func (s *Server) SendBatchStart(refID, batchType string, params ...string) error {
	p := make([]string, 0, 2+len(params))
	p = append(p, "+"+refID, batchType)
	p = append(p, params...)
	msg := &ircv3.P10Message{
		Source:  s.serverNumeric,
		Command: "BA",
		Params:  p,
	}
	return s.SendP10(msg)
}

// SendBatchEnd sends a BATCH -refid line.
func (s *Server) SendBatchEnd(refID string) error {
	msg := &ircv3.P10Message{
		Source:  s.serverNumeric,
		Command: "BA",
		Params:  []string{"-" + refID},
	}
	return s.SendP10(msg)
}

// SendWithLabel sends a response message, handling labeled-response
// batch wrapping automatically.
func (s *Server) SendWithLabel(lc *ircv3.LabelContext, msg *ircv3.P10Message) error {
	if lc == nil || !lc.HasLabel() {
		return s.SendP10(msg)
	}

	// Track response count
	needsBatch := lc.IncrementResponse()

	if needsBatch {
		// Transitioning to multi-response — open a batch
		batchMsg := lc.StartBatch(s.serverNumeric)
		if batchMsg != nil {
			if err := s.SendP10(batchMsg); err != nil {
				return fmt.Errorf("failed to start labeled-response batch: %w", err)
			}
		}
	}

	lc.ApplyToMessage(msg)
	return s.SendP10(msg)
}

// FinishLabel closes the labeled-response batch if one was opened.
func (s *Server) FinishLabel(lc *ircv3.LabelContext) error {
	if lc == nil || lc.BatchRefID == "" {
		return nil
	}
	endMsg := lc.EndBatch(s.serverNumeric)
	if endMsg != nil {
		return s.SendP10(endMsg)
	}
	return nil
}

// SendXReply sends an XREPLY response back to Cathexis.
// Used for chathistory and other XQUERY responses.
func (s *Server) SendXReply(target, routing, text string) error {
	msg := &ircv3.P10Message{
		Source:  s.serverNumeric,
		Command: "XR", // XREPLY token in P10
		Params:  []string{target, routing, text},
	}
	return s.SendP10(msg)
}

// isPseudoClient returns true if the given numeric belongs to one of
// Acid's pseudo-clients.
func (s *Server) isPseudoClient(numeric string) bool {
	s.pseudoMu.RLock()
	defer s.pseudoMu.RUnlock()
	_, ok := s.pseudoClients[numeric]
	return ok
}

// pseudoClientNick returns the nick for a pseudo-client numeric.
func (s *Server) pseudoClientNick(numeric string) string {
	s.pseudoMu.RLock()
	defer s.pseudoMu.RUnlock()
	pc, ok := s.pseudoClients[numeric]
	if !ok {
		return ""
	}
	return pc.Nick
}

// tokenToCommand maps P10 tokens to full IRC command names.
// Delegates to p10.CommandFromToken (pre-built reverse map, O(1) lookup).
func tokenToCommand(token string) string {
	return p10.CommandFromToken(token)
}

// commandToToken maps full IRC command names to P10 tokens.
// Delegates to p10.TokenFromCommand (single source of truth).
func commandToToken(cmd string) string {
	return p10.TokenFromCommand(cmd)
}

// serverTimeFromTags extracts server-time from tags, falling back to now.
func serverTimeFromTags(tags *ircv3.Tags) time.Time {
	if tags == nil {
		return time.Now()
	}
	ts, ok := tags.Get("time")
	if !ok || ts == "" {
		return time.Now()
	}
	t, err := ircv3.ParseServerTime(ts)
	if err != nil {
		return time.Now()
	}
	return t
}
