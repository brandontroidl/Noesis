// Copyright (c) Cathexis Development
// SPDX-License-Identifier: GPL-2.0-only
//
// ircv3/botmode.go — IRCv3 bot-mode (+B) support for Acid pseudo-clients.
//
// Per the IRCv3 bot-mode spec, services and bots must set user mode +B
// so clients can identify them as automated. Cathexis advertises the
// bot-mode CAP and shows +B in WHO/WHOIS responses.
//
// Acid must:
//   1. Include +B in the mode string when introducing pseudo-clients
//      during BURST (the N line)
//   2. Include the draft/bot tag on messages from pseudo-clients
//      (when Cathexis negotiates message-tags with clients)

package ircv3

// BotModeChar is the user mode character for bot identification.
const BotModeChar = 'B'

// BotModeString is "+B" for use in P10 N (NICK) lines during BURST.
const BotModeString = "+B"

// BotTagKey is the IRCv3 bot tag key.
// Using the draft/ prefix until ratified, matching Cathexis.
const BotTagKey = "draft/bot"

// ApplyBotTag adds the draft/bot tag to an outgoing message
// from a pseudo-client. This is a boolean tag (no value).
func ApplyBotTag(msg *P10Message) {
	msg.EnsureTags()
	msg.Tags.Set(BotTagKey, "")
}

// BuildNickModes returns the mode string for a pseudo-client
// introduction during BURST. Includes +B (bot) and any additional
// modes the pseudo-client needs.
//
// Standard Acid pseudo-client modes: +oikB
//   +o = IRC operator
//   +i = invisible
//   +k = services client (immune to kill)
//   +B = bot mode
func BuildNickModes(extraModes string) string {
	base := "+oikB"
	if extraModes == "" {
		return base
	}
	// Merge extra modes into base, deduplicating
	modes := make(map[rune]bool)
	for _, c := range base[1:] { // skip '+'
		modes[c] = true
	}
	for _, c := range extraModes {
		if c != '+' && c != '-' {
			modes[c] = true
		}
	}
	result := "+"
	for c := range modes {
		result += string(c)
	}
	return result
}
