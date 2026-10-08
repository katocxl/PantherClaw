// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
)

// KeySize is the AES-256 key size in bytes.
const KeySize = 32

// ErrDecrypt is the only error returned for failed decryption, whatever the
// cause (wrong key, wrong context, tampering), so callers learn nothing more.
var ErrDecrypt = errors.New("crypto: decryption failed")

// AEAD is AES-256-GCM with a random 96-bit nonce per message, prepended to
// the ciphertext (cipher.NewGCMWithRandomNonce). A key must not encrypt more
// than 2^32 messages; DEKs rotate long before that (SB-3).
type AEAD struct {
	gcm cipher.AEAD
}

// NewAEAD returns an AEAD for a 32-byte key.
func NewAEAD(key []byte) (*AEAD, error) {
	if len(key) != KeySize {
		return nil, fmt.Errorf("crypto: AES-256 key must be %d bytes, got %d", KeySize, len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("crypto: %w", err)
	}
	gcm, err := cipher.NewGCMWithRandomNonce(block)
	if err != nil {
		return nil, fmt.Errorf("crypto: %w", err)
	}
	return &AEAD{gcm: gcm}, nil
}

// Seal encrypts plaintext bound to aad and returns nonce‖ciphertext‖tag.
func (a *AEAD) Seal(plaintext, aad []byte) []byte {
	return a.gcm.Seal(nil, nil, plaintext, aad) //nolint:gosec // G407: NewGCMWithRandomNonce generates the nonce; it requires a nil nonce argument
}

// Open decrypts a Seal output bound to aad.
func (a *AEAD) Open(ciphertext, aad []byte) ([]byte, error) {
	if len(ciphertext) < a.gcm.Overhead() {
		return nil, ErrDecrypt
	}
	pt, err := a.gcm.Open(nil, nil, ciphertext, aad)
	if err != nil {
		return nil, ErrDecrypt
	}
	return pt, nil
}

// NewKey returns a fresh random 32-byte key.
func NewKey() []byte {
	k := make([]byte, KeySize)
	_, _ = rand.Read(k) // crypto/rand.Read never fails (Go ≥ 1.24)
	return k
}
