// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package ids

import (
	"bytes"
	"errors"
	"strings"
	"testing"
	"time"
)

type testKind struct{}

func (testKind) KindName() string { return "test" }

type testID = ID[testKind]

func TestNewV7Layout(t *testing.T) {
	at := time.Date(2026, 10, 8, 12, 30, 0, 123_000_000, time.UTC)
	u := newV7At(at)
	if u.Version() != 7 {
		t.Fatalf("version = %d, want 7", u.Version())
	}
	if !u.rfcVariant() {
		t.Fatalf("variant bits = %08b, want 10xxxxxx", u[8])
	}
	if got := u.Time(); !got.Equal(at.Truncate(time.Millisecond)) {
		t.Fatalf("embedded time = %v, want %v", got, at)
	}
}

func TestNewV7Unique(t *testing.T) {
	seen := make(map[UUID]bool, 10_000)
	for range 10_000 {
		u := NewV7()
		if seen[u] {
			t.Fatalf("duplicate UUID %s", u)
		}
		seen[u] = true
	}
}

func TestNewV7TimeOrdered(t *testing.T) {
	a := newV7At(time.UnixMilli(1_000))
	b := newV7At(time.UnixMilli(2_000))
	if bytes.Compare(a[:], b[:]) >= 0 {
		t.Fatalf("UUIDv7 from earlier ms (%s) does not sort before later (%s)", a, b)
	}
}

func TestParseUUIDRoundTrip(t *testing.T) {
	u := NewV7()
	got, err := ParseUUID(u.String())
	if err != nil || got != u {
		t.Fatalf("ParseUUID(%s) = %s, %v", u, got, err)
	}
	upper, err := ParseUUID(strings.ToUpper(u.String()))
	if err != nil || upper != u {
		t.Fatalf("uppercase parse = %s, %v", upper, err)
	}
}

func TestParseUUIDRejectsNonCanonical(t *testing.T) {
	valid := "0190a1b2-c3d4-7e5f-8a6b-7c8d9e0f1a2b"
	for _, s := range []string{
		"",
		"{" + valid + "}",
		"urn:uuid:" + valid,
		strings.ReplaceAll(valid, "-", ""),
		valid + " ",
		" " + valid,
		"0190a1b2-c3d4-7e5f-8a6b-7c8d9e0f1a2g",
		"0190a1b2_c3d4-7e5f-8a6b-7c8d9e0f1a2b",
		"0190a1b2-c3d4-7e5f-8a6b-7c8d9e0f1a2\x00",
	} {
		if _, err := ParseUUID(s); !errors.Is(err, ErrInvalidUUID) {
			t.Errorf("ParseUUID(%q) err = %v, want ErrInvalidUUID", s, err)
		}
	}
}

func TestParseTypedID(t *testing.T) {
	id := New[testKind]()
	got, err := Parse[testKind](id.String())
	if err != nil || got != id {
		t.Fatalf("Parse = %v, %v; want %v", got, err, id)
	}
	if id.Kind() != "test" {
		t.Fatalf("Kind = %q", id.Kind())
	}
}

func TestParseTypedIDRejects(t *testing.T) {
	cases := map[string]string{
		"nil UUID":     "00000000-0000-0000-0000-000000000000",
		"version 4":    "9b2e1c3a-5f6d-4e7f-8a9b-0c1d2e3f4a5b",
		"MS variant":   "0190a1b2-c3d4-7e5f-ca6b-7c8d9e0f1a2b",
		"NCS variant":  "0190a1b2-c3d4-7e5f-0a6b-7c8d9e0f1a2b",
		"not a UUID":   "org-1",
		"long garbage": strings.Repeat("x", 200),
	}
	for name, s := range cases {
		_, err := Parse[testKind](s)
		if !errors.Is(err, ErrInvalidID) {
			t.Errorf("%s: Parse(%q) err = %v, want ErrInvalidID", name, s, err)
		}
		if err != nil && len(err.Error()) > 120 {
			t.Errorf("%s: error message not truncated: %d bytes", name, len(err.Error()))
		}
	}
}

func TestTextRoundTrip(t *testing.T) {
	id := New[testKind]()
	b, err := id.MarshalText()
	if err != nil {
		t.Fatal(err)
	}
	var back testID
	if err := back.UnmarshalText(b); err != nil || back != id {
		t.Fatalf("UnmarshalText = %v, %v; want %v", back, err, id)
	}
	var zero testID
	if b, _ := zero.MarshalText(); len(b) != 0 {
		t.Fatalf("zero ID marshals to %q, want empty", b)
	}
	back = id
	if err := back.UnmarshalText(nil); err != nil || !back.IsZero() {
		t.Fatalf("empty text should yield zero ID, got %v, %v", back, err)
	}
}

func TestValueZeroIsNull(t *testing.T) {
	var zero testID
	v, err := zero.Value()
	if err != nil || v != nil {
		t.Fatalf("zero.Value() = %v, %v; want nil (SQL NULL)", v, err)
	}
	id := New[testKind]()
	v, err = id.Value()
	if err != nil || v != id.String() {
		t.Fatalf("Value() = %v, %v", v, err)
	}
}

func TestScan(t *testing.T) {
	id := New[testKind]()
	u := id.UUID()
	for name, src := range map[string]any{
		"string":   id.String(),
		"text":     []byte(id.String()),
		"binary":   u[:],
		"array":    [16]byte(u),
		"nil→zero": nil,
	} {
		var got testID
		if err := got.Scan(src); err != nil {
			t.Fatalf("%s: Scan error %v", name, err)
		}
		want := id
		if src == nil {
			want = testID{}
		}
		if got != want {
			t.Fatalf("%s: Scan = %v, want %v", name, got, want)
		}
	}
	var got testID
	if err := got.Scan(42); !errors.Is(err, ErrInvalidID) {
		t.Fatalf("Scan(int) err = %v, want ErrInvalidID", err)
	}
	var nilBytes [16]byte
	if err := got.Scan(nilBytes[:]); !errors.Is(err, ErrInvalidID) {
		t.Fatalf("Scan(nil binary UUID) err = %v, want ErrInvalidID", err)
	}
}

func TestPlatformOrgIsValidAndNotZero(t *testing.T) {
	if PlatformOrg.IsZero() {
		t.Fatal("PlatformOrg must not be the zero ID")
	}
	if _, err := Parse[Org](PlatformOrg.String()); err != nil {
		t.Fatalf("PlatformOrg does not round-trip: %v", err)
	}
}

func TestTypedIDsAreDistinctTypes(t *testing.T) {
	// Compile-time property: an OrgID is not assignable to a testID. This test
	// documents the intent; the assertion is that this file compiles without
	// such an assignment being possible.
	var org OrgID
	var other testID
	if any(org) == any(other) {
		t.Fatal("distinct ID kinds compare equal through interfaces")
	}
}

func FuzzParseUUID(f *testing.F) {
	f.Add("0190a1b2-c3d4-7e5f-8a6b-7c8d9e0f1a2b")
	f.Add("")
	f.Add("{0190a1b2-c3d4-7e5f-8a6b-7c8d9e0f1a2b}")
	f.Fuzz(func(t *testing.T, s string) {
		u, err := ParseUUID(s)
		if err != nil {
			return
		}
		if !strings.EqualFold(u.String(), s) {
			t.Fatalf("accepted %q but formats as %q", s, u.String())
		}
	})
}
