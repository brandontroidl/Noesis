// Copyright (c) Cathexis Development
// SPDX-License-Identifier: GPL-2.0-only
//
// ircv3/message.go — P10 message with IRCv3 tag support.
//
// A P10Message wraps a raw P10 line with parsed IRCv3 tags.
// This struct flows through Acid's entire dispatch pipeline:
//
//   Raw P10 line from Cathexis
//     → ParseP10Line() → P10Message{Tags, Source, Command, Params}
//     → server.go dispatch handler
//     → module handler (weather, trivia, etc.)
//     → BuildP10Line() → raw P10 line back to Cathexis
//
// The key insight: P10 lines from Cathexis now carry an optional
// @tags prefix before the source numeric. Acid must preserve these
// tags through its pipeline and inject its own tags on outgoing lines.

package ircv3

import (
	"strings"
)

// P10Message represents a parsed P10 protocol line with IRCv3 tags.
type P10Message struct {
	// Tags contains IRCv3 message tags (may be nil if no tags present).
	Tags *Tags

	// Source is the P10 source numeric (e.g., "ABAAB" for a user,
	// "AB" for a server).
	Source string

	// Command is the P10 command or token (e.g., "P" for PRIVMSG,
	// "N" for NICK, "B" for BURST).
	Command string

	// Params holds the command parameters. The last param may have
	// been prefixed with ':' on the wire (trailing parameter).
	Params []string

	// Raw preserves the original line for debugging.
	Raw string
}

// ParseP10Line parses a raw P10 line into a P10Message, extracting
// any IRCv3 tag prefix.
//
// P10 format (without tags):
//   ABAAB P #channel :Hello world
//
// P10 format (with Cathexis IRCv3 tags):
//   @time=2026-04-08T15:30:00.000Z;msgid=abc123 ABAAB P #channel :Hello world
//
// Server messages (no source):
//   PASS :password
//   SERVER servername ...
func ParseP10Line(line string) *P10Message {
	msg := &P10Message{Raw: line}

	if line == "" {
		return msg
	}

	pos := 0

	// Parse optional tag prefix
	if line[0] == '@' {
		space := strings.IndexByte(line, ' ')
		if space < 0 {
			// Malformed: tags but nothing else
			msg.Tags = ParseTags(line[1:])
			return msg
		}
		msg.Tags = ParseTags(line[1:space])
		pos = space + 1
		// Skip extra spaces
		for pos < len(line) && line[pos] == ' ' {
			pos++
		}
	}

	if pos >= len(line) {
		return msg
	}

	// The rest is standard P10: Source Command Params...
	// First token is source numeric (or command for server messages like PASS/SERVER)
	rest := line[pos:]
	parts := splitP10(rest)

	if len(parts) == 0 {
		return msg
	}

	// Determine if first token is a source or a command.
	// P10 source numerics are uppercase alphanumeric, typically 2 or 5 chars.
	// Server commands like PASS, SERVER, ERROR have no source.
	first := parts[0]
	if isP10Numeric(first) && len(parts) > 1 {
		msg.Source = first
		msg.Command = parts[1]
		if len(parts) > 2 {
			msg.Params = parts[2:]
		}
	} else {
		// No source — server registration message
		msg.Command = first
		if len(parts) > 1 {
			msg.Params = parts[1:]
		}
	}

	return msg
}

// BuildP10Line constructs a P10 wire-format line from the message.
// If Tags is non-nil and non-empty, prepends the @tags prefix.
func (msg *P10Message) BuildP10Line() string {
	var b strings.Builder

	// Tag prefix
	if msg.Tags != nil && msg.Tags.Len() > 0 {
		b.WriteString(msg.Tags.Prefix())
		b.WriteByte(' ')
	}

	// Source
	if msg.Source != "" {
		b.WriteString(msg.Source)
		b.WriteByte(' ')
	}

	// Command
	b.WriteString(msg.Command)

	// Params
	for i, p := range msg.Params {
		b.WriteByte(' ')
		if i == len(msg.Params)-1 && (strings.ContainsRune(p, ' ') || p == "" || p[0] == ':') {
			b.WriteByte(':')
		}
		b.WriteString(p)
	}

	return b.String()
}

// GetTag is a convenience method to get a tag value from the message.
func (msg *P10Message) GetTag(key string) (string, bool) {
	if msg.Tags == nil {
		return "", false
	}
	return msg.Tags.Get(key)
}

// SetTag sets a tag on the message, creating the Tags map if needed.
func (msg *P10Message) SetTag(key, value string) {
	if msg.Tags == nil {
		msg.Tags = NewTags()
	}
	msg.Tags.Set(key, value)
}

// EnsureTags ensures the message has a Tags struct (creates if nil).
func (msg *P10Message) EnsureTags() {
	if msg.Tags == nil {
		msg.Tags = NewTags()
	}
}

// InjectStandardTags adds @time and @msgid tags if not already present.
// Call this on every outgoing message from Acid.
func (msg *P10Message) InjectStandardTags() {
	msg.EnsureTags()
	if !msg.Tags.Has("time") {
		msg.Tags.Set("time", ServerTimeNow())
	}
	if !msg.Tags.Has("msgid") {
		msg.Tags.Set("msgid", GenerateMsgID())
	}
}

// InjectAccountTag adds the @account= tag for the given account name.
// All messages from Acid pseudo-clients should carry this.
func (msg *P10Message) InjectAccountTag(account string) {
	if account == "" {
		return
	}
	msg.EnsureTags()
	msg.Tags.Set("account", account)
}

// Param returns the i-th parameter, or empty string if out of range.
func (msg *P10Message) Param(i int) string {
	if i < 0 || i >= len(msg.Params) {
		return ""
	}
	return msg.Params[i]
}

// Trailing returns the last parameter (the "trailing" param after ':').
func (msg *P10Message) Trailing() string {
	if len(msg.Params) == 0 {
		return ""
	}
	return msg.Params[len(msg.Params)-1]
}

// splitP10 splits a P10 line into tokens, handling the trailing ':' parameter.
func splitP10(line string) []string {
	var parts []string
	for {
		line = strings.TrimLeft(line, " ")
		if line == "" {
			break
		}
		if line[0] == ':' {
			// Trailing parameter — everything after ':'
			parts = append(parts, line[1:])
			break
		}
		idx := strings.IndexByte(line, ' ')
		if idx < 0 {
			parts = append(parts, line)
			break
		}
		parts = append(parts, line[:idx])
		line = line[idx+1:]
	}
	return parts
}

// isP10Numeric returns true if s looks like a P10 numeric
// (2 chars for server, 5 chars for user, all base64 chars).
func isP10Numeric(s string) bool {
	if len(s) != 2 && len(s) != 5 {
		return false
	}
	for _, c := range s {
		if !isBase64Char(c) {
			return false
		}
	}
	return true
}

// isBase64Char returns true if c is a valid P10 base64 character.
// P10 base64: A-Z a-z 0-9 [ ]
func isBase64Char(c rune) bool {
	return (c >= 'A' && c <= 'Z') ||
		(c >= 'a' && c <= 'z') ||
		(c >= '0' && c <= '9') ||
		c == '[' || c == ']'
}
