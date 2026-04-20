// Copyright (c) Cathexis Development
// SPDX-License-Identifier: GPL-2.0-only
//
// server/s2s_crypto.go — HMAC-SHA3-512 server-to-server authentication.
//
// Implements the cathexis-s2s-hmac-sha3-v2 and sacert-sha3-v2 key
// derivation schemes for P10 link authentication against Cathexis 1.6.0+.
// Cathexis sends a challenge during link negotiation, and Noesis must
// respond with the correct HMAC-SHA3-512 signature.
//
// Key derivation (matches Cathexis pq_derive_s2s_mac_key):
//   label     = "cathexis-s2s-hmac-sha3-v2"   (s2s HMAC path)
//             | "cathexis-s2s-sacert-sha3-v2" (s2s SASL-certify path)
//   derived   = HKDF-SHA3-512(password, salt=nil, info=label, len=64)
//   signature = HMAC-SHA3-512(derived, message)
//
// Legacy v1 (HMAC-SHA256 / "cathexis-s2s-hmac-v1") is retained as a
// configurable scheme for pre-1.6.0 interop during a transition window.
// Set hmac_scheme = "cathexis-s2s-hmac-v1" in noesis.toml to pin the
// old scheme when linking to pre-1.6.0 Cathexis. Default is v2.

package server

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"hash"

	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/sha3"
)

// Derivation labels — must byte-for-byte match Cathexis pq_crypto.c.
const (
	LabelHMACv2   = "cathexis-s2s-hmac-sha3-v2"
	LabelSacertV2 = "cathexis-s2s-sacert-sha3-v2"
	LabelHMACv1   = "cathexis-s2s-hmac-v1" // legacy
	LabelSacertV1 = "sacert-v1"            // legacy
)

// S2SCrypto handles HMAC authentication for the P10 link.
// The `scheme` field selects between v2 (HMAC-SHA3-512 / default) and
// legacy v1 (HMAC-SHA256) for interop with pre-1.6.0 Cathexis.
type S2SCrypto struct {
	key    []byte
	scheme string
}

// NewS2SCrypto creates a new S2S crypto handler. If scheme is empty,
// defaults to the v2 scheme (cathexis-s2s-hmac-sha3-v2).
func NewS2SCrypto(key string, scheme string) *S2SCrypto {
	if scheme == "" {
		scheme = LabelHMACv2
	}
	return &S2SCrypto{
		key:    []byte(key),
		scheme: scheme,
	}
}

// isV2 returns true if this crypto handler uses the v2 (SHA3-512) scheme.
func (sc *S2SCrypto) isV2() bool {
	return sc.scheme == LabelHMACv2 || sc.scheme == LabelSacertV2
}

// hashFn returns the appropriate hash.Hash constructor for this scheme.
func (sc *S2SCrypto) hashFn() func() hash.Hash {
	if sc.isV2() {
		return sha3.New512
	}
	return sha256.New
}

// Sign computes the HMAC signature for a challenge using the derived key.
// Output length is 128 hex chars (SHA3-512) in v2, 64 hex chars (SHA-256) in v1.
func (sc *S2SCrypto) Sign(challenge string) string {
	derived := sc.deriveKey(challenge)
	mac := hmac.New(sc.hashFn(), derived)
	mac.Write([]byte(challenge))
	return hex.EncodeToString(mac.Sum(nil))
}

// SignMessage computes the per-message HMAC for a P10 line using the
// s2s derived key (matches Cathexis s2s_derive_keys + compute_link_mac).
//
//	v2: derived   = HKDF-SHA3-512(password, "cathexis-s2s-hmac-sha3-v2", 64)
//	    signature = HMAC-SHA3-512(derived, message)  →  128 hex chars
//
//	v1: derived   = HMAC-SHA256(password, "cathexis-s2s-hmac-v1")
//	    signature = HMAC-SHA256(derived, message)    →  64 hex chars
func (sc *S2SCrypto) SignMessage(line string) string {
	derivedKey := sc.deriveMessageKey()
	mac := hmac.New(sc.hashFn(), derivedKey)
	mac.Write([]byte(line))
	return hex.EncodeToString(mac.Sum(nil))
}

// deriveMessageKey derives the per-message HMAC key using the configured scheme.
// Matches Cathexis pq_derive_s2s_mac_key (v2) or legacy s2s_derive_keys (v1).
func (sc *S2SCrypto) deriveMessageKey() []byte {
	if sc.isV2() {
		// HKDF-SHA3-512: 64-byte output keyed on the password via an
		// empty salt, with the label as the info input. Matches the
		// Cathexis C implementation via EVP_KDF_fetch("HKDF").
		kdf := hkdf.New(sha3.New512, sc.key, nil, []byte(LabelHMACv2))
		out := make([]byte, 64)
		if _, err := kdf.Read(out); err != nil {
			// HKDF over SHA3-512 can emit up to 255*64 bytes; 64 is
			// trivial. A non-nil error here is impossible in practice
			// but returning a nil key would silently auth-fail, so
			// panic loudly — this indicates a stdlib bug or OOM.
			panic(fmt.Sprintf("noesis: HKDF-SHA3-512 derivation failed: %v", err))
		}
		return out
	}

	// Legacy v1: HMAC-SHA256(password, label) — 32-byte output.
	dkMac := hmac.New(sha256.New, sc.key)
	dkMac.Write([]byte(LabelHMACv1))
	return dkMac.Sum(nil)
}

// Verify checks if a signature is valid for a challenge.
func (sc *S2SCrypto) Verify(challenge, signature string) bool {
	expected := sc.Sign(challenge)
	return hmacEqual(expected, signature)
}

// deriveKey performs challenge-binding key derivation based on the scheme.
// This is used by the legacy Sign()/Verify() challenge-response flow.
func (sc *S2SCrypto) deriveKey(challenge string) []byte {
	switch sc.scheme {
	case LabelHMACv2:
		return sc.deriveV2(challenge, LabelHMACv2)
	case LabelSacertV2:
		return sc.deriveV2(challenge, LabelSacertV2)
	case LabelHMACv1:
		return sc.deriveV1(challenge, LabelHMACv1)
	case LabelSacertV1:
		return sc.deriveV1(challenge, LabelSacertV1)
	default:
		// Raw key, no derivation (testing / custom schemes).
		return sc.key
	}
}

// deriveV2: HKDF-SHA3-512(key, info=label||challenge, len=64).
// Challenge is bound into the info field so the derived key can't be
// replayed against a different challenge.
func (sc *S2SCrypto) deriveV2(challenge, label string) []byte {
	info := append([]byte(label), []byte(challenge)...)
	kdf := hkdf.New(sha3.New512, sc.key, nil, info)
	out := make([]byte, 64)
	if _, err := kdf.Read(out); err != nil {
		panic(fmt.Sprintf("noesis: HKDF-SHA3-512 derivation failed: %v", err))
	}
	return out
}

// deriveV1: HMAC-SHA256(key, label || challenge) — legacy.
func (sc *S2SCrypto) deriveV1(challenge, label string) []byte {
	mac := hmac.New(sha256.New, sc.key)
	mac.Write([]byte(label))
	mac.Write([]byte(challenge))
	return mac.Sum(nil)
}

// hmacEqual performs constant-time comparison of two hex strings.
// Returns false if either string is malformed hex.
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
