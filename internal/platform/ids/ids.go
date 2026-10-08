// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package ids provides typed UUIDv7 identifiers.
//
// Raw strings and UUIDs never cross layers (BUILD_GUIDE §3.1): every entity has
// its own ID type, so an AgentID cannot be passed where an OrgID is expected.
// A new entity declares a Kind and an alias:
//
//	type Agent struct{}
//	func (Agent) KindName() string { return "agent" }
//	type AgentID = ids.ID[Agent]
//
// IDs implement encoding.TextMarshaler/TextUnmarshaler and the database/sql
// Valuer/Scanner interfaces, so they work with JSON, protobuf string fields
// and pgx without conversions.
package ids

import (
	"database/sql/driver"
	"errors"
	"fmt"
)

// Kind names the entity an ID refers to. Kinds are empty struct types.
type Kind interface {
	KindName() string
}

// ID is an identifier of an entity of kind K. The zero value is "no ID" and is
// never valid as a reference.
type ID[K Kind] struct {
	u UUID
}

// ErrInvalidID reports an identifier that is not a canonical, non-nil UUIDv7.
var ErrInvalidID = errors.New("ids: invalid identifier")

// New returns a fresh UUIDv7 identifier.
func New[K Kind]() ID[K] { return ID[K]{u: NewV7()} }

// Parse parses a canonical UUIDv7 string. Nil UUIDs, other versions and other
// variants are rejected: every PantherClaw identifier is minted as UUIDv7.
func Parse[K Kind](s string) (ID[K], error) {
	u, err := ParseUUID(s)
	if err != nil {
		return ID[K]{}, invalid[K](s)
	}
	return FromUUID[K](u)
}

// MustParse is Parse for compile-time constants; it panics on invalid input
// and must only be used in package-level variable initialization and tests.
func MustParse[K Kind](s string) ID[K] {
	id, err := Parse[K](s)
	if err != nil {
		panic(err)
	}
	return id
}

// FromUUID converts a UUID read from a trusted store into a typed ID, applying
// the same validation as Parse.
func FromUUID[K Kind](u UUID) (ID[K], error) {
	if u.IsZero() || u.Version() != 7 || !u.rfcVariant() {
		return ID[K]{}, invalid[K](u.String())
	}
	return ID[K]{u: u}, nil
}

func invalid[K Kind](s string) error {
	var k K
	if len(s) > 64 {
		s = s[:64] + "…"
	}
	return fmt.Errorf("%w: %s %q", ErrInvalidID, k.KindName(), s)
}

// UUID returns the underlying UUID.
func (id ID[K]) UUID() UUID { return id.u }

// IsZero reports whether id is the zero value.
func (id ID[K]) IsZero() bool { return id.u.IsZero() }

// String returns the canonical lowercase UUID form.
func (id ID[K]) String() string { return id.u.String() }

// Kind returns the entity kind name, for diagnostics.
func (id ID[K]) Kind() string {
	var k K
	return k.KindName()
}

// MarshalText implements encoding.TextMarshaler. The zero ID marshals as an
// empty string.
func (id ID[K]) MarshalText() ([]byte, error) {
	if id.IsZero() {
		return []byte{}, nil
	}
	return []byte(id.u.String()), nil
}

// UnmarshalText implements encoding.TextUnmarshaler. An empty string yields
// the zero ID; anything else must be a valid UUIDv7.
func (id *ID[K]) UnmarshalText(b []byte) error {
	if len(b) == 0 {
		*id = ID[K]{}
		return nil
	}
	parsed, err := Parse[K](string(b))
	if err != nil {
		return err
	}
	*id = parsed
	return nil
}

// Value implements driver.Valuer. The zero ID is stored as SQL NULL so that a
// forgotten ID violates NOT NULL constraints instead of matching the nil UUID.
func (id ID[K]) Value() (driver.Value, error) {
	if id.IsZero() {
		return nil, nil
	}
	return id.u.String(), nil
}

// Scan implements sql.Scanner for uuid columns (text or 16-byte binary).
func (id *ID[K]) Scan(src any) error {
	switch v := src.(type) {
	case nil:
		*id = ID[K]{}
		return nil
	case string:
		return id.UnmarshalText([]byte(v))
	case []byte:
		if len(v) == 16 {
			parsed, err := FromUUID[K](UUID(v))
			if err != nil {
				return err
			}
			*id = parsed
			return nil
		}
		return id.UnmarshalText(v)
	case [16]byte:
		parsed, err := FromUUID[K](UUID(v))
		if err != nil {
			return err
		}
		*id = parsed
		return nil
	default:
		return fmt.Errorf("%w: cannot scan %T into %s ID", ErrInvalidID, src, id.Kind())
	}
}
