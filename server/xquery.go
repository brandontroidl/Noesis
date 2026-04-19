// Copyright (c) Cathexis Development
// SPDX-License-Identifier: GPL-2.0-only
//
// server/xquery.go — XQUERY/XREPLY handler for Cathexis↔Acid chathistory.
//
// When a client sends CHATHISTORY to Cathexis, Cathexis proxies it as:
//   XQ <target-server> <routing-info> :CHATHISTORY <subcommand> <params>
//
// Acid receives the XQ, processes the chathistory request, and responds:
//   XR <source-server> <routing-info> :response-data
//
// Chathistory subcommands per IRCv3 spec:
//   LATEST <target> [timestamp|msgid] <limit>
//   BEFORE <target> <timestamp|msgid> <limit>
//   AFTER  <target> <timestamp|msgid> <limit>
//   AROUND <target> <timestamp|msgid> <limit>
//   BETWEEN <target> <timestamp|msgid> <timestamp|msgid> <limit>
//   TARGETS <timestamp> <timestamp> <limit>

package server

import (
	"fmt"
	"log"
	"strconv"
	"strings"

	"github.com/brandontroidl/noesis/ircv3"
	"github.com/brandontroidl/noesis/store"
)

// handleXQuery processes an incoming XQUERY from Cathexis.
func (s *Server) handleXQuery(msg *ircv3.P10Message) {
	// XQ format: <source> XQ <target-server> <routing> :<query>
	if len(msg.Params) < 3 {
		log.Printf("[XQUERY] malformed: too few params")
		return
	}

	routing := msg.Param(1)
	query := msg.Trailing()

	// Extract label context for labeled-response
	lc := ircv3.NewLabelContext(msg.Tags)

	// Parse the query
	parts := strings.Fields(query)
	if len(parts) < 1 {
		s.sendXReplyError(routing, lc, "FAIL", "XQUERY", "INVALID_PARAMS", "Empty query")
		return
	}

	switch strings.ToUpper(parts[0]) {
	case "CHATHISTORY":
		s.handleChathistoryQuery(routing, parts[1:], lc, msg)
	default:
		s.sendXReplyError(routing, lc, "FAIL", "XQUERY", "UNKNOWN_COMMAND",
			fmt.Sprintf("Unknown XQUERY type: %s", parts[0]))
	}
}

// handleChathistoryQuery processes a CHATHISTORY subcommand.
func (s *Server) handleChathistoryQuery(routing string, args []string, lc *ircv3.LabelContext, origMsg *ircv3.P10Message) {
	if len(args) < 1 {
		s.sendXReplyError(routing, lc, "FAIL", "CHATHISTORY", "INVALID_PARAMS", "Missing subcommand")
		return
	}

	subcommand := strings.ToUpper(args[0])

	switch subcommand {
	case "LATEST":
		// LATEST <target> [timestamp|msgid] <limit>
		if len(args) < 3 {
			s.sendXReplyError(routing, lc, "FAIL", "CHATHISTORY", "INVALID_PARAMS",
				"LATEST requires: <target> [timestamp|*] <limit>")
			return
		}
		target := args[1]
		cursor := args[2]
		limit := "50" // default
		if len(args) > 3 {
			limit = args[3]
		} else if cursor != "*" {
			// cursor is actually limit if only 3 args and target has no cursor
			limit = cursor
			cursor = "*"
		}
		s.chathistoryLatest(routing, target, cursor, limit, lc)

	case "BEFORE":
		if len(args) < 4 {
			s.sendXReplyError(routing, lc, "FAIL", "CHATHISTORY", "INVALID_PARAMS",
				"BEFORE requires: <target> <timestamp|msgid> <limit>")
			return
		}
		s.chathistoryBefore(routing, args[1], args[2], args[3], lc)

	case "AFTER":
		if len(args) < 4 {
			s.sendXReplyError(routing, lc, "FAIL", "CHATHISTORY", "INVALID_PARAMS",
				"AFTER requires: <target> <timestamp|msgid> <limit>")
			return
		}
		s.chathistoryAfter(routing, args[1], args[2], args[3], lc)

	case "AROUND":
		if len(args) < 4 {
			s.sendXReplyError(routing, lc, "FAIL", "CHATHISTORY", "INVALID_PARAMS",
				"AROUND requires: <target> <timestamp|msgid> <limit>")
			return
		}
		s.chathistoryAround(routing, args[1], args[2], args[3], lc)

	case "BETWEEN":
		if len(args) < 5 {
			s.sendXReplyError(routing, lc, "FAIL", "CHATHISTORY", "INVALID_PARAMS",
				"BETWEEN requires: <target> <start> <end> <limit>")
			return
		}
		s.chathistoryBetween(routing, args[1], args[2], args[3], args[4], lc)

	case "TARGETS":
		if len(args) < 4 {
			s.sendXReplyError(routing, lc, "FAIL", "CHATHISTORY", "INVALID_PARAMS",
				"TARGETS requires: <from> <to> <limit>")
			return
		}
		s.chathistoryTargets(routing, args[1], args[2], args[3], lc)

	default:
		s.sendXReplyError(routing, lc, "FAIL", "CHATHISTORY", "UNKNOWN_COMMAND",
			fmt.Sprintf("Unknown subcommand: %s", subcommand))
	}
}

// chathistoryLatest retrieves the most recent messages for a target.
func (s *Server) chathistoryLatest(routing, target, cursor, limit string, lc *ircv3.LabelContext) {
	if s.messages == nil {
		s.sendXReplyError(routing, lc, "FAIL", "CHATHISTORY", "MESSAGE_ERROR", "History not available")
		return
	}

	n := parseLimit(limit)
	msgs := s.messages.Latest(target, cursor, n)
	s.sendChathistoryBatch(routing, target, msgs, lc)
}

// chathistoryBefore retrieves messages before a given cursor.
func (s *Server) chathistoryBefore(routing, target, cursor, limit string, lc *ircv3.LabelContext) {
	if s.messages == nil {
		s.sendXReplyError(routing, lc, "FAIL", "CHATHISTORY", "MESSAGE_ERROR", "History not available")
		return
	}

	n := parseLimit(limit)
	msgs := s.messages.Before(target, cursor, n)
	s.sendChathistoryBatch(routing, target, msgs, lc)
}

// chathistoryAfter retrieves messages after a given cursor.
func (s *Server) chathistoryAfter(routing, target, cursor, limit string, lc *ircv3.LabelContext) {
	if s.messages == nil {
		s.sendXReplyError(routing, lc, "FAIL", "CHATHISTORY", "MESSAGE_ERROR", "History not available")
		return
	}

	n := parseLimit(limit)
	msgs := s.messages.After(target, cursor, n)
	s.sendChathistoryBatch(routing, target, msgs, lc)
}

// chathistoryAround retrieves messages around a given cursor.
func (s *Server) chathistoryAround(routing, target, cursor, limit string, lc *ircv3.LabelContext) {
	if s.messages == nil {
		s.sendXReplyError(routing, lc, "FAIL", "CHATHISTORY", "MESSAGE_ERROR", "History not available")
		return
	}

	n := parseLimit(limit)
	msgs := s.messages.Around(target, cursor, n)
	s.sendChathistoryBatch(routing, target, msgs, lc)
}

// chathistoryBetween retrieves messages between two cursors.
func (s *Server) chathistoryBetween(routing, target, start, end, limit string, lc *ircv3.LabelContext) {
	if s.messages == nil {
		s.sendXReplyError(routing, lc, "FAIL", "CHATHISTORY", "MESSAGE_ERROR", "History not available")
		return
	}

	n := parseLimit(limit)
	msgs := s.messages.Between(target, start, end, n)
	s.sendChathistoryBatch(routing, target, msgs, lc)
}

// chathistoryTargets retrieves channels/users with history in a time range.
func (s *Server) chathistoryTargets(routing, from, to, limit string, lc *ircv3.LabelContext) {
	if s.messages == nil {
		s.sendXReplyError(routing, lc, "FAIL", "CHATHISTORY", "MESSAGE_ERROR", "History not available")
		return
	}

	fromTime, _ := ircv3.ParseServerTime(from)
	toTime, _ := ircv3.ParseServerTime(to)
	n := parseLimit(limit)

	targets := s.messages.Targets(fromTime, toTime, n)

	refID := ircv3.GenerateRefID()
	_ = s.SendBatchStart(refID, ircv3.BatchChatHistory, "*")
	for _, t := range targets {
		msg := &ircv3.P10Message{
			Tags:    ircv3.TagsFromMap(map[string]string{"batch": refID}),
			Source:  s.serverNumeric,
			Command: "XR",
			Params:  []string{routing, fmt.Sprintf("CHATHISTORY TARGETS %s", t)},
		}
		_ = s.SendP10(msg)
	}
	_ = s.SendBatchEnd(refID)
	_ = s.FinishLabel(lc)
}

// sendChathistoryBatch wraps a slice of stored messages in a chathistory batch.
func (s *Server) sendChathistoryBatch(routing, target string, msgs []store.StoredMessage, lc *ircv3.LabelContext) {
	refID := ircv3.GenerateRefID()

	if err := s.SendBatchStart(refID, ircv3.BatchChatHistory, target); err != nil {
		log.Printf("[CHATHISTORY] failed to start batch: %v", err)
		return
	}

	for _, m := range msgs {
		tags := ircv3.NewTags()
		tags.Set("batch", refID)
		tags.Set("time", ircv3.FormatServerTime(m.Time))
		tags.Set("msgid", m.MsgID)
		if m.Account != "" {
			tags.Set("account", m.Account)
		}

		msg := &ircv3.P10Message{
			Tags:    tags,
			Source:  s.serverNumeric,
			Command: "XR",
			Params:  []string{routing, fmt.Sprintf(":%s %s %s :%s", m.Source, m.Command, m.Target, m.Text)},
		}
		_ = s.SendP10(msg)
	}

	if err := s.SendBatchEnd(refID); err != nil {
		log.Printf("[CHATHISTORY] failed to end batch: %v", err)
	}

	_ = s.FinishLabel(lc)
}

// parseLimit parses a limit string, defaulting to 50.
func parseLimit(s string) int {
	n, err := strconv.Atoi(s)
	if err != nil || n <= 0 {
		return 50
	}
	if n > 500 {
		return 500
	}
	return n
}

// sendXReplyError sends a standard-reply error via XREPLY.
func (s *Server) sendXReplyError(routing string, lc *ircv3.LabelContext, replyType, command, code, message string) {
	reply := fmt.Sprintf("%s %s %s :%s", replyType, command, code, message)
	msg := &ircv3.P10Message{
		Source:  s.serverNumeric,
		Command: "XR",
		Params:  []string{routing, reply},
	}
	if lc != nil {
		lc.ApplyToMessage(msg)
	}
	_ = s.SendP10(msg)
	_ = s.FinishLabel(lc)
}
