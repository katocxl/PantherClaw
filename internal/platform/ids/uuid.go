// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package ids

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"time"
)

// UUID is an RFC 9562 UUID in its 16-byte binary form.
type UUID [16]byte

// ErrInvalidUUID reports a string that is not a canonical UUID.
var ErrInvalidUUID = errors.New("ids: invalid UUID")

// NewV7 returns a new version 7 UUID: a 48-bit Unix millisecond timestamp
// followed by 74 bits from crypto/rand (RFC 9562 §5.7). crypto/rand.Read never
// returns an error (Go ≥ 1.24), so generation cannot fail.
func NewV7() UUID {
	return newV7At(time.Now())
}

func newV7At(t time.Time) UUID {
	var u UUID
	ms := uint64(t.UnixMilli())
	var ts [8]byte
	binary.BigEndian.PutUint64(ts[:], ms)
	copy(u[0:6], ts[2:8])
	_, _ = rand.Read(u[6:])
	u[6] = (u[6] & 0x0f) | 0x70 // version 7
	u[8] = (u[8] & 0x3f) | 0x80 // RFC 9562 variant (10xx)
	return u
}

// ParseUUID parses the canonical 36-character form
// (xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx, either letter case). Braced, URN and
// unhyphenated forms are rejected so that every identifier has one spelling.
func ParseUUID(s string) (UUID, error) {
	var u UUID
	if len(s) != 36 || s[8] != '-' || s[13] != '-' || s[18] != '-' || s[23] != '-' {
		return u, ErrInvalidUUID
	}
	j := 0
	for i := 0; i < 36; {
		if i == 8 || i == 13 || i == 18 || i == 23 {
			i++
			continue
		}
		hi, ok1 := fromHex(s[i])
		lo, ok2 := fromHex(s[i+1])
		if !ok1 || !ok2 {
			return UUID{}, ErrInvalidUUID
		}
		u[j] = hi<<4 | lo
		j++
		i += 2
	}
	return u, nil
}

// String returns the canonical lowercase form.
func (u UUID) String() string {
	var buf [36]byte
	hex.Encode(buf[0:8], u[0:4])
	buf[8] = '-'
	hex.Encode(buf[9:13], u[4:6])
	buf[13] = '-'
	hex.Encode(buf[14:18], u[6:8])
	buf[18] = '-'
	hex.Encode(buf[19:23], u[8:10])
	buf[23] = '-'
	hex.Encode(buf[24:36], u[10:16])
	return string(buf[:])
}

// IsZero reports whether u is the nil UUID.
func (u UUID) IsZero() bool { return u == UUID{} }

// Version returns the UUID version nibble.
func (u UUID) Version() int { return int(u[6] >> 4) }

// rfcVariant reports whether u uses the RFC 9562 variant.
func (u UUID) rfcVariant() bool { return u[8]&0xc0 == 0x80 }

// Time returns the timestamp embedded in a version 7 UUID.
func (u UUID) Time() time.Time {
	var ts [8]byte
	copy(ts[2:8], u[0:6])
	return time.UnixMilli(int64(binary.BigEndian.Uint64(ts[:]))).UTC() //nolint:gosec // G115: 48-bit value fits in int64
}

func fromHex(c byte) (byte, bool) {
	switch {
	case '0' <= c && c <= '9':
		return c - '0', true
	case 'a' <= c && c <= 'f':
		return c - 'a' + 10, true
	case 'A' <= c && c <= 'F':
		return c - 'A' + 10, true
	default:
		return 0, false
	}
}
