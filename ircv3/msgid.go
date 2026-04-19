// Copyright (c) Cathexis Development
// SPDX-License-Identifier: GPL-2.0-only
//
// ircv3/msgid.go — Message ID generation for IRCv3 msgid tag.
//
// Generates unique message IDs using crypto/rand. Format is a 128-bit
// hex string (32 chars), matching the format used by Cathexis and Synaxis.
// Every PRIVMSG, NOTICE, TAGMSG, KICK, TOPIC, and similar user-visible
// message originating from Acid must carry a unique @msgid= tag.

package ircv3

import (
	"crypto/rand"
	"encoding/hex"
	"sync"
)

var (
	msgidBuf  [16]byte
	msgidLock sync.Mutex
)

// GenerateMsgID returns a new unique message ID as a 32-char hex string.
// Thread-safe via mutex. Uses crypto/rand for uniqueness.
func GenerateMsgID() string {
	msgidLock.Lock()
	defer msgidLock.Unlock()

	_, err := rand.Read(msgidBuf[:])
	if err != nil {
		// Fallback: this should never happen, but if it does
		// we still need a unique-ish value. Use timestamp + counter.
		// In practice crypto/rand failing means the system is broken.
		panic("crypto/rand failed: " + err.Error())
	}
	return hex.EncodeToString(msgidBuf[:])
}
