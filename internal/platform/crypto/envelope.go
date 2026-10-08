// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package crypto

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/katocxl/pantherclaw/internal/platform/ids"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
)

const (
	envelopeV1      byte = 0x01
	envelopeHdrSize      = 1 + 4
)

// ErrUnknownDEK reports a ciphertext whose DEK version is not available.
var ErrUnknownDEK = errors.New("crypto: unknown data encryption key")

// DEKSource supplies per-org, per-purpose data encryption keys. The keys
// package implements it with DEKs stored wrapped by a KEK (SB-3).
type DEKSource interface {
	// CurrentDEK returns the DEK to encrypt new values with.
	CurrentDEK(ctx context.Context, org ids.OrgID, purpose string) (version uint32, key pclog.Secret[[]byte], err error)
	// DEK returns a specific DEK version for decryption.
	DEK(ctx context.Context, org ids.OrgID, purpose string, version uint32) (pclog.Secret[[]byte], error)
}

// Envelope encrypts database fields with per-org, per-purpose DEKs. The
// stored blob is version(1) ‖ dek_version(4) ‖ nonce ‖ ciphertext ‖ tag, and
// the AAD binds purpose, DEK version, org, table, column and row id (HR-062).
type Envelope struct {
	deks DEKSource
}

// NewEnvelope returns an Envelope backed by deks.
func NewEnvelope(deks DEKSource) *Envelope { return &Envelope{deks: deks} }

// Encrypt encrypts plaintext for the given storage location.
func (e *Envelope) Encrypt(ctx context.Context, fc FieldContext, purpose string, plaintext []byte) ([]byte, error) {
	version, key, err := e.deks.CurrentDEK(ctx, fc.Org, purpose)
	if err != nil {
		return nil, fmt.Errorf("crypto: current DEK: %w", err)
	}
	aad, err := fieldAAD(fc, purpose, version)
	if err != nil {
		return nil, err
	}
	a, err := NewAEAD(key.Reveal())
	if err != nil {
		return nil, err
	}
	out := make([]byte, envelopeHdrSize, envelopeHdrSize+len(plaintext)+28)
	out[0] = envelopeV1
	binary.BigEndian.PutUint32(out[1:5], version)
	return append(out, a.Seal(plaintext, aad)...), nil
}

// Decrypt decrypts a blob produced by Encrypt for the same location. Any
// mismatch (other org, table, column, row, purpose, or tampering) returns
// ErrDecrypt.
func (e *Envelope) Decrypt(ctx context.Context, fc FieldContext, purpose string, blob []byte) ([]byte, error) {
	if len(blob) < envelopeHdrSize || blob[0] != envelopeV1 {
		return nil, ErrDecrypt
	}
	version := binary.BigEndian.Uint32(blob[1:5])
	aad, err := fieldAAD(fc, purpose, version)
	if err != nil {
		return nil, err
	}
	key, err := e.deks.DEK(ctx, fc.Org, purpose, version)
	if err != nil {
		if errors.Is(err, ErrUnknownDEK) {
			return nil, ErrDecrypt
		}
		return nil, fmt.Errorf("crypto: DEK %d: %w", version, err)
	}
	a, err := NewAEAD(key.Reveal())
	if err != nil {
		return nil, err
	}
	return a.Open(blob[envelopeHdrSize:], aad)
}
