// Copyright (c) Cathexis Development
// SPDX-License-Identifier: GPL-2.0-only
//
// p10/p10.go — P10 protocol codec: base64 numerics and encoding.
//
// P10 uses a custom base64 alphabet for server and client numerics:
//   ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789[]
//
// Server numerics are 2 chars (0-4095), client numerics are 3 chars
// within the server's namespace (0-262143). A full user numeric is
// 5 chars: 2 server + 3 client (e.g., "ABAAB").

package p10

import (
	"fmt"
	"strings"
	"sync"
)

// P10 base64 alphabet
const base64Chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789[]"

// IntToBase64 converts an integer to a P10 base64 string of the given width.
func IntToBase64(val, width int) string {
	if width <= 0 {
		return ""
	}
	result := make([]byte, width)
	for i := width - 1; i >= 0; i-- {
		result[i] = base64Chars[val%64]
		val /= 64
	}
	return string(result)
}

// Base64ToInt converts a P10 base64 string to an integer.
func Base64ToInt(s string) int {
	val := 0
	for _, c := range s {
		val = val*64 + base64Index(byte(c))
	}
	return val
}

// base64Index returns the index of a character in the P10 base64 alphabet.
func base64Index(c byte) int {
	switch {
	case c >= 'A' && c <= 'Z':
		return int(c - 'A')
	case c >= 'a' && c <= 'z':
		return int(c-'a') + 26
	case c >= '0' && c <= '9':
		return int(c-'0') + 52
	case c == '[':
		return 62
	case c == ']':
		return 63
	default:
		return 0
	}
}

// ServerNumeric returns the 2-char P10 server numeric for an integer.
func ServerNumeric(n int) string {
	return IntToBase64(n, 2)
}

// ClientNumeric returns the 3-char P10 client numeric for an integer.
func ClientNumeric(n int) string {
	return IntToBase64(n, 3)
}

// UserNumeric returns the full 5-char P10 user numeric (server + client).
func UserNumeric(serverNum, clientNum int) string {
	return ServerNumeric(serverNum) + ClientNumeric(clientNum)
}

// ParseUserNumeric splits a 5-char user numeric into server and client parts.
func ParseUserNumeric(numeric string) (serverPart, clientPart string) {
	if len(numeric) < 5 {
		return numeric, ""
	}
	return numeric[:2], numeric[2:]
}

// IsServerNumeric returns true if the string is a 2-char P10 server numeric.
func IsServerNumeric(s string) bool {
	return len(s) == 2 && isBase64String(s)
}

// IsUserNumeric returns true if the string is a 5-char P10 user numeric.
func IsUserNumeric(s string) bool {
	return len(s) == 5 && isBase64String(s)
}

// isBase64String checks if all characters are valid P10 base64.
func isBase64String(s string) bool {
	for _, c := range s {
		if !isBase64Char(c) {
			return false
		}
	}
	return true
}

// isBase64Char returns true if c is a valid P10 base64 character.
func isBase64Char(c rune) bool {
	return (c >= 'A' && c <= 'Z') ||
		(c >= 'a' && c <= 'z') ||
		(c >= '0' && c <= '9') ||
		c == '[' || c == ']'
}

// NumericAllocator manages client numeric allocation within a server namespace.
type NumericAllocator struct {
	mu            sync.Mutex
	serverNumeric string
	serverInt     int
	nextClient    int
	maxClients    int
	inUse         map[int]bool
}

// NewNumericAllocator creates a new allocator for the given server numeric.
func NewNumericAllocator(serverNum int, maxClients int) *NumericAllocator {
	if maxClients <= 0 {
		maxClients = 64 // default
	}
	if maxClients > 262143 {
		maxClients = 262143 // P10 max: 3 base64 chars
	}
	return &NumericAllocator{
		serverNumeric: ServerNumeric(serverNum),
		serverInt:     serverNum,
		nextClient:    1, // 0 is reserved
		maxClients:    maxClients,
		inUse:         make(map[int]bool),
	}
}

// Allocate returns the next available full user numeric (5 chars).
func (na *NumericAllocator) Allocate() (string, error) {
	na.mu.Lock()
	defer na.mu.Unlock()
	for i := 0; i < na.maxClients; i++ {
		candidate := (na.nextClient + i) % na.maxClients
		if candidate == 0 {
			candidate = 1
		}
		if !na.inUse[candidate] {
			na.inUse[candidate] = true
			na.nextClient = candidate + 1
			return na.serverNumeric + ClientNumeric(candidate), nil
		}
	}
	return "", fmt.Errorf("no available client numerics (max: %d)", na.maxClients)
}

// Release frees a client numeric for reuse.
func (na *NumericAllocator) Release(numeric string) {
	na.mu.Lock()
	defer na.mu.Unlock()
	if len(numeric) != 5 {
		return
	}
	clientPart := numeric[2:]
	clientInt := Base64ToInt(clientPart)
	delete(na.inUse, clientInt)
}

// ServerNum returns the 2-char server numeric string.
func (na *NumericAllocator) ServerNum() string {
	return na.serverNumeric
}

// P10 command tokens — maps between full names and P10 tokens.
// Used by ircv3/message.go for dispatch and by modules for building messages.
var TokenMap = map[string]string{
	"PRIVMSG":      "P",
	"NOTICE":       "O",
	"JOIN":         "J",
	"PART":         "L",
	"QUIT":         "Q",
	"KICK":         "K",
	"MODE":         "M",
	"NICK":         "N",
	"TOPIC":        "T",
	"INVITE":       "I",
	"BURST":        "B",
	"END_OF_BURST": "EB",
	"EOB_ACK":      "EA",
	"SERVER":       "S",
	"SQUIT":        "SQ",
	"KILL":         "D",
	"GLINE":        "GL",
	"WALLOPS":      "WA",
	"SETTIME":      "SE",
	"RPING":        "RI",
	"RPONG":        "RO",
	"WHOIS":        "W",
	"ACCOUNT":      "AC",
	"BATCH":        "BA",
	"TAGMSG":       "TG",
	"XQUERY":       "XQ",
	"XREPLY":       "XR",
	"SVSNICK":      "SN",
	"SVSMODE":      "SM",
	"AWAY":         "A",
	"CLEARMODE":    "CM",
	"OPMODE":       "OM",
	"CREATE":       "C",
	"DESTRUCT":     "DE",
	"DESYNCH":      "DS",
	"PING":         "G",
	"PONG":         "Z",
	"INFO":         "F",
	"LINKS":        "LI",
	"STATS":        "R",
	"VERSION":      "V",
	"PASS":         "PA",
	"ERROR":        "Y",
}

// ReverseTokenMap maps P10 tokens to full command names (pre-built for O(1) lookup).
var ReverseTokenMap = buildReverseMap()

func buildReverseMap() map[string]string {
	m := make(map[string]string, len(TokenMap))
	for cmd, tok := range TokenMap {
		m[tok] = cmd
	}
	return m
}

// CommandFromToken returns the full command name for a P10 token.
func CommandFromToken(token string) string {
	if cmd, ok := ReverseTokenMap[token]; ok {
		return cmd
	}
	return token
}

// TokenFromCommand returns the P10 token for a full command name.
func TokenFromCommand(cmd string) string {
	if tok, ok := TokenMap[strings.ToUpper(cmd)]; ok {
		return tok
	}
	return cmd
}

// FormatTimestamp formats a Unix timestamp for P10 BURST/NICK lines.
func FormatTimestamp(ts int64) string {
	return fmt.Sprintf("%d", ts)
}

// BuildModeString combines a set of mode characters into a +modes string.
func BuildModeString(modes ...rune) string {
	if len(modes) == 0 {
		return ""
	}
	seen := make(map[rune]bool)
	var b strings.Builder
	b.WriteByte('+')
	for _, m := range modes {
		if !seen[m] && m != '+' && m != '-' {
			b.WriteRune(m)
			seen[m] = true
		}
	}
	return b.String()
}
