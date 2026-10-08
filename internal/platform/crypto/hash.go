// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package crypto holds PantherClaw's cryptographic building blocks, built only
// on the Go standard library (ADR-0012, SB-3): hashing helpers, AES-256-GCM
// field encryption with context-binding AAD, per-org envelope encryption, and
// HPKE (X-Wing) sealing. Signatures live in package crypto/sign.
//
// Import it with an alias, for example:
//
//	import pccrypto "github.com/katocxl/pantherclaw/internal/platform/crypto"
package crypto

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
)

// SHA256 returns the SHA-256 digest of b.
func SHA256(b []byte) []byte {
	sum := sha256.Sum256(b)
	return sum[:]
}

// B64 encodes b as base64url without padding (PAP/1 §2).
func B64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// FromB64 decodes base64url without padding. Padded or standard-alphabet
// input is rejected so that each value has one encoding.
func FromB64(s string) ([]byte, error) { return base64.RawURLEncoding.Strict().DecodeString(s) }

// HashB64 returns base64url(SHA-256(b)), the PAP/1 hash encoding.
func HashB64(b []byte) string { return B64(SHA256(b)) }

// HMACSHA256 returns HMAC-SHA256(key, msg).
func HMACSHA256(key, msg []byte) []byte {
	m := hmac.New(sha256.New, key)
	m.Write(msg)
	return m.Sum(nil)
}

// Equal compares two byte slices in constant time (for MACs, hashes of
// secrets and tokens). Slices of different length are unequal.
func Equal(a, b []byte) bool { return subtle.ConstantTimeCompare(a, b) == 1 }
