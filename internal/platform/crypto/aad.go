// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package crypto

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// ErrInvalidContext reports an incomplete or oversized encryption context.
var ErrInvalidContext = errors.New("crypto: invalid encryption context")

const maxContextField = 255

// FieldContext identifies exactly where an encrypted value is stored. It is
// bound into the AEAD associated data, so a ciphertext copied to another
// org, table, column or row fails to decrypt (HR-062, T-016).
type FieldContext struct {
	Org    ids.OrgID
	Table  string
	Column string
	RowID  string
}

func (c FieldContext) validate() error {
	if c.Org.IsZero() {
		return fmt.Errorf("%w: missing org", ErrInvalidContext)
	}
	for name, v := range map[string]string{"table": c.Table, "column": c.Column, "row id": c.RowID} {
		if v == "" || len(v) > maxContextField {
			return fmt.Errorf("%w: %s must be 1..%d bytes", ErrInvalidContext, name, maxContextField)
		}
	}
	return nil
}

// AAD builds unambiguous associated data: a domain-separation label followed
// by length-prefixed fields. Length prefixes make the encoding injective, so
// ("ab","c") and ("a","bc") never collide.
type AAD struct {
	b   []byte
	err error
}

// NewAAD starts associated data with a domain-separation label such as
// "pc-field-v1".
func NewAAD(label string) *AAD {
	a := &AAD{}
	return a.Str(label)
}

// Str appends a length-prefixed string field (1..255 bytes).
func (a *AAD) Str(s string) *AAD {
	if a.err != nil {
		return a
	}
	if len(s) == 0 || len(s) > maxContextField {
		a.err = fmt.Errorf("%w: field length %d", ErrInvalidContext, len(s))
		return a
	}
	a.b = append(a.b, byte(len(s))) //nolint:gosec // G115: len(s) is checked to be 1..255 above
	a.b = append(a.b, s...)
	return a
}

// Bytes appends a length-prefixed byte field (1..255 bytes).
func (a *AAD) Bytes(b []byte) *AAD { return a.Str(string(b)) }

// Uint32 appends a fixed-width big-endian integer.
func (a *AAD) Uint32(n uint32) *AAD {
	if a.err == nil {
		a.b = binary.BigEndian.AppendUint32(a.b, n)
	}
	return a
}

// Build returns the encoded associated data or the first error.
func (a *AAD) Build() ([]byte, error) {
	if a.err != nil {
		return nil, a.err
	}
	return a.b, nil
}

// fieldAAD binds the format version, purpose, DEK version and field context.
func fieldAAD(c FieldContext, purpose string, dekVersion uint32) ([]byte, error) {
	if err := c.validate(); err != nil {
		return nil, err
	}
	org := c.Org.UUID()
	return NewAAD("pc-field-v1").
		Str(purpose).
		Uint32(dekVersion).
		Bytes(org[:]).
		Str(c.Table).
		Str(c.Column).
		Str(c.RowID).
		Build()
}
