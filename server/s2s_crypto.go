// Copyright (c) Cathexis Development
// SPDX-License-Identifier: GPL-2.0-only
//
// server/s2s_crypto.go — HMAC-SHA256 server-to-server authentication.
//
// Implements the cathexis-s2s-hmac-v1 and sacert-v1 key derivation
// schemes for P10 link authentication. Cathexis sends a challenge
// during link negotiation, and Acid must respond with the correct
// HMAC-SHA256 signature.

package server

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

// S2SCrypto handles HMAC-SHA256 authentication for the P10 link.
type S2SCrypto struct {
	key    []byte
	scheme string
}

// NewS2SCrypto creates a new S2S crypto handler.
func NewS2SCrypto(key string, scheme string) *S2SCrypto {
	if scheme == "" {
		scheme = "cathexis-s2s-hmac-v1"
	}
	return &S2SCrypto{
		key:    []byte(key),
		scheme: scheme,
	}
}

// Sign computes the HMAC-SHA256 signature for a challenge.
func (sc *S2SCrypto) Sign(challenge string) string {
	derived := sc.deriveKey(challenge)
	mac := hmac.New(sha256.New, derived)
	mac.Write([]byte(challenge))
	return hex.EncodeToString(mac.Sum(nil))
}

// SignMessage computes the per-message HMAC-SHA256 for a P10 line.
// Uses the derived HMAC key matching Cathexis s2s_derive_keys():
//   derived = HMAC-SHA256(password, "cathexis-s2s-hmac-v1")
//   signature = HMAC-SHA256(derived, message)
func (sc *S2SCrypto) SignMessage(line string) string {
	// Step 1: Derive the per-message key (matches s2s_derive_keys in Cathexis)
	dkMac := hmac.New(sha256.New, sc.key)
	dkMac.Write([]byte("cathexis-s2s-hmac-v1"))
	derivedKey := dkMac.Sum(nil) // 32 bytes

	// Step 2: Sign the message with the derived key
	mac := hmac.New(sha256.New, derivedKey)
	mac.Write([]byte(line))
	return hex.EncodeToString(mac.Sum(nil))
}

// Verify checks if a signature is valid for a challenge.
func (sc *S2SCrypto) Verify(challenge, signature string) bool {
	expected := sc.Sign(challenge)
	return hmacEqual(expected, signature)
}

// deriveKey performs key derivation based on the configured scheme.
func (sc *S2SCrypto) deriveKey(challenge string) []byte {
	switch sc.scheme {
	case "cathexis-s2s-hmac-v1":
		return sc.deriveCathexisV1(challenge)
	case "sacert-v1":
		return sc.deriveSacertV1(challenge)
	default:
		// Raw key, no derivation
		return sc.key
	}
}

// deriveCathexisV1 derives a key using the cathexis-s2s-hmac-v1 scheme.
// HMAC-SHA256(key, "cathexis-s2s-hmac-v1" || challenge)
func (sc *S2SCrypto) deriveCathexisV1(challenge string) []byte {
	mac := hmac.New(sha256.New, sc.key)
	mac.Write([]byte("cathexis-s2s-hmac-v1"))
	mac.Write([]byte(challenge))
	return mac.Sum(nil)
}

// deriveSacertV1 derives a key using the sacert-v1 scheme.
// HMAC-SHA256(key, "sacert-v1" || challenge)
func (sc *S2SCrypto) deriveSacertV1(challenge string) []byte {
	mac := hmac.New(sha256.New, sc.key)
	mac.Write([]byte("sacert-v1"))
	mac.Write([]byte(challenge))
	return mac.Sum(nil)
}

// hmacEqual performs constant-time comparison of two hex strings.
func hmacEqual(a, b string) bool {
	aBytes, err1 := hex.DecodeString(a)
	bBytes, err2 := hex.DecodeString(b)
	if err1 != nil || err2 != nil {
		return false
	}
	return hmac.Equal(aBytes, bBytes)
}

// GenerateChallenge creates a challenge string for outgoing auth.
func GenerateChallenge(serverName string, ts int64) string {
	return fmt.Sprintf("%s:%d", serverName, ts)
}
