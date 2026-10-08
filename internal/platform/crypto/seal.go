// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package crypto

import (
	"crypto/hpke"
	"encoding/binary"
	"errors"
	"fmt"
)

// ErrSealedFormat reports a malformed sealed blob.
var ErrSealedFormat = errors.New("crypto: malformed sealed blob")

const sealedV1 byte = 0x01

// The single HPKE suite PantherClaw uses for sealed credentials (SB-3,
// PAP-1 §2): KEM MLKEM768-X25519 (X-Wing), KDF HKDF-SHA256, AEAD AES-256-GCM.
func suite() (hpke.KEM, hpke.KDF, hpke.AEAD) {
	return hpke.MLKEM768X25519(), hpke.HKDFSHA256(), hpke.AES256GCM()
}

// SealPrivateKey is an X-Wing decapsulation key (a broker key, HR-060).
type SealPrivateKey struct{ k hpke.PrivateKey }

// SealPublicKey is an X-Wing encapsulation key.
type SealPublicKey struct{ k hpke.PublicKey }

// GenerateSealKey returns a new X-Wing key pair.
func GenerateSealKey() (*SealPrivateKey, error) {
	kem, _, _ := suite()
	k, err := kem.GenerateKey()
	if err != nil {
		return nil, fmt.Errorf("crypto: generate seal key: %w", err)
	}
	return &SealPrivateKey{k: k}, nil
}

// ParseSealPrivateKey deserializes a private key produced by Bytes.
func ParseSealPrivateKey(b []byte) (*SealPrivateKey, error) {
	kem, _, _ := suite()
	k, err := kem.NewPrivateKey(b)
	if err != nil {
		return nil, fmt.Errorf("crypto: parse seal private key: %w", err)
	}
	return &SealPrivateKey{k: k}, nil
}

// ParseSealPublicKey deserializes a public key produced by Bytes.
func ParseSealPublicKey(b []byte) (*SealPublicKey, error) {
	kem, _, _ := suite()
	k, err := kem.NewPublicKey(b)
	if err != nil {
		return nil, fmt.Errorf("crypto: parse seal public key: %w", err)
	}
	return &SealPublicKey{k: k}, nil
}

// Bytes serializes the private key. Treat the result as a secret.
func (p *SealPrivateKey) Bytes() ([]byte, error) { return p.k.Bytes() }

// PublicKey returns the matching public key.
func (p *SealPrivateKey) PublicKey() *SealPublicKey { return &SealPublicKey{k: p.k.PublicKey()} }

// Bytes serializes the public key.
func (p *SealPublicKey) Bytes() []byte { return p.k.Bytes() }

// Seal encrypts plaintext to pub. info binds the context (for credentials:
// org, connection, version and allowed hosts, HR-060) and aad is additional
// authenticated data. The result is version(1) ‖ len(enc)(2) ‖ enc ‖ ct.
func Seal(pub *SealPublicKey, info, aad, plaintext []byte) ([]byte, error) {
	if len(info) == 0 {
		return nil, fmt.Errorf("%w: info must bind a context", ErrInvalidContext)
	}
	_, kdf, aead := suite()
	enc, s, err := hpke.NewSender(pub.k, kdf, aead, info)
	if err != nil {
		return nil, fmt.Errorf("crypto: hpke sender: %w", err)
	}
	ct, err := s.Seal(aad, plaintext)
	if err != nil {
		return nil, fmt.Errorf("crypto: hpke seal: %w", err)
	}
	out := make([]byte, 0, 3+len(enc)+len(ct))
	out = append(out, sealedV1)
	out = binary.BigEndian.AppendUint16(out, uint16(len(enc))) //nolint:gosec // G115: X-Wing enc is 1120 bytes
	out = append(out, enc...)
	return append(out, ct...), nil
}

// Open decrypts a Seal output. Any mismatch in key, info, aad or content
// returns ErrDecrypt.
func Open(priv *SealPrivateKey, info, aad, sealed []byte) ([]byte, error) {
	if len(sealed) < 3 || sealed[0] != sealedV1 {
		return nil, ErrSealedFormat
	}
	n := int(binary.BigEndian.Uint16(sealed[1:3]))
	if len(sealed) < 3+n {
		return nil, ErrSealedFormat
	}
	enc, ct := sealed[3:3+n], sealed[3+n:]
	_, kdf, aead := suite()
	r, err := hpke.NewRecipient(enc, priv.k, kdf, aead, info)
	if err != nil {
		return nil, ErrDecrypt
	}
	pt, err := r.Open(aad, ct)
	if err != nil {
		return nil, ErrDecrypt
	}
	return pt, nil
}
