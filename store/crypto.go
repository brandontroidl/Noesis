// Copyright (c) Cathexis Development
// SPDX-License-Identifier: GPL-2.0-only
//
// store/crypto.go — AES-256-GCM encryption for data at rest.
//
// File format:
//   [4 bytes: magic "AX3E"]
//   [12 bytes: random IV/nonce]
//   [N bytes: AES-256-GCM ciphertext]
//   [16 bytes: GCM authentication tag (appended by GCM Seal)]
//
// Key derivation:
//   key = HMAC-SHA256(passphrase, "cathexis-noesis-encrypt-v1")

package store

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"os"
)

const (
	cryptoMagic   = "AX3E"
	cryptoIVLen   = 12
	cryptoKeyLen  = 32
	cryptoHdrLen  = 4 // magic only
)

var (
	ErrNotEncrypted = errors.New("file is not encrypted")
	ErrAuthFailed   = errors.New("decryption authentication failed (wrong key?)")
)

// CryptoStore provides transparent encryption for file I/O.
type CryptoStore struct {
	key     [cryptoKeyLen]byte
	enabled bool
}

// NewCryptoStore derives an AES-256 key from the passphrase and returns a CryptoStore.
// If passphrase is empty, encryption is disabled (passthrough).
func NewCryptoStore(passphrase string) *CryptoStore {
	cs := &CryptoStore{}
	if passphrase == "" {
		return cs
	}

	mac := hmac.New(sha256.New, []byte(passphrase))
	mac.Write([]byte("cathexis-noesis-encrypt-v1"))
	copy(cs.key[:], mac.Sum(nil))
	cs.enabled = true
	return cs
}

// Enabled returns true if encryption is active.
func (cs *CryptoStore) Enabled() bool {
	return cs.enabled
}

// IsEncrypted checks if a file has the AX3E magic header.
func IsEncrypted(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	magic := make([]byte, 4)
	if _, err := f.Read(magic); err != nil {
		return false
	}
	return string(magic) == cryptoMagic
}

// EncryptBytes encrypts plaintext and returns the encrypted blob.
func (cs *CryptoStore) EncryptBytes(plaintext []byte) ([]byte, error) {
	if !cs.enabled {
		return plaintext, nil
	}

	block, err := aes.NewCipher(cs.key[:])
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	iv := make([]byte, cryptoIVLen)
	if _, err := rand.Read(iv); err != nil {
		return nil, err
	}

	ciphertext := gcm.Seal(nil, iv, plaintext, nil)

	// Build output: magic + iv + ciphertext (includes tag)
	out := make([]byte, 0, cryptoHdrLen+cryptoIVLen+len(ciphertext))
	out = append(out, []byte(cryptoMagic)...)
	out = append(out, iv...)
	out = append(out, ciphertext...)
	return out, nil
}

// DecryptBytes decrypts an encrypted blob and returns plaintext.
// If the data is not encrypted (no magic header), returns it as-is.
func (cs *CryptoStore) DecryptBytes(data []byte) ([]byte, error) {
	if len(data) < cryptoHdrLen {
		return data, nil
	}
	if string(data[:4]) != cryptoMagic {
		// Not encrypted — return as plaintext (transparent migration)
		return data, nil
	}
	if !cs.enabled {
		return nil, errors.New("file is encrypted but no encryption key configured")
	}

	if len(data) < cryptoHdrLen+cryptoIVLen+16 {
		return nil, errors.New("encrypted file too short")
	}

	iv := data[cryptoHdrLen : cryptoHdrLen+cryptoIVLen]
	ciphertext := data[cryptoHdrLen+cryptoIVLen:]

	block, err := aes.NewCipher(cs.key[:])
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	plaintext, err := gcm.Open(nil, iv, ciphertext, nil)
	if err != nil {
		return nil, ErrAuthFailed
	}
	return plaintext, nil
}

// ReadFile reads a file, decrypting if necessary.
func (cs *CryptoStore) ReadFile(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return cs.DecryptBytes(data)
}

// WriteFile writes data to a file, encrypting if enabled.
func (cs *CryptoStore) WriteFile(path string, plaintext []byte, perm os.FileMode) error {
	data, err := cs.EncryptBytes(plaintext)
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, perm)
}
