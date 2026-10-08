// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

import (
	"bytes"
	"encoding/hex"
	"errors"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

var (
	testOrg = ids.MustParse[ids.Org]("01920000-0000-7000-8000-00000000000a")
	testAt  = time.Date(2026, 10, 8, 12, 0, 0, 123456789, time.UTC)
)

func entry(t *testing.T, n int) Entry {
	t.Helper()
	body, err := CanonicalBody(map[string]any{"n": n, "note": "test"})
	if err != nil {
		t.Fatal(err)
	}
	id, _ := ids.ParseUUID("01920000-0000-7000-8000-0000000001" + string(rune('0'+n/10)) + string(rune('0'+n%10)))
	return Entry{Org: testOrg, ID: id, Kind: "audit.test_event", Actor: Actor{Type: "system", ID: "test"}, OccurredAt: testAt, Body: body}
}

func TestCanonicalIsStableAndLocked(t *testing.T) {
	e := entry(t, 1)
	c, err := e.Canonical(1)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"actor":{"id":"test","type":"system"},"body":{"n":1,"note":"test"},"id":"01920000-0000-7000-8000-000000000101",` +
		`"kind":"audit.test_event","org":"01920000-0000-7000-8000-00000000000a","seq":1,"ts":"2026-10-08T12:00:00.123456Z","v":1}`
	if string(c) != want {
		t.Fatalf("canonical form changed:\n got %s\nwant %s", c, want)
	}
	// The hash format is consumed by offline verifiers: lock it with a golden value.
	h := LinkHash(GenesisHash, c)
	if got := hex.EncodeToString(h); got != goldenHash {
		t.Fatalf("link hash = %s, want %s", got, goldenHash)
	}
}

// goldenHash = SHA-256(32 zero bytes ‖ canonical form above).
const goldenHash = "d159a8a56589f7480efdb2f1e9f32a29f781cee877935e4ea94f7b614ae04162" // cross-checked with openssl dgst -sha256

func TestCanonicalBodyRejects(t *testing.T) {
	for name, v := range map[string]any{
		"array":  []int{1},
		"string": "x",
		"bad":    map[string]any{"f": func() {}},
	} {
		if _, err := CanonicalBody(v); !errors.Is(err, ErrInvalidEntry) {
			t.Errorf("%s: err = %v", name, err)
		}
	}
	e := entry(t, 1)
	e.Body = []byte(`{"b":1, "a":2}`) // not canonical (order, whitespace)
	if err := e.Validate(); !errors.Is(err, ErrInvalidEntry) {
		t.Fatalf("non-canonical body accepted: %v", err)
	}
	e.Body = bytes.Repeat([]byte("x"), MaxBodyBytes+1)
	if err := e.Validate(); !errors.Is(err, ErrInvalidEntry) {
		t.Fatal("oversized body accepted")
	}
}

func TestValidateFields(t *testing.T) {
	for name, mutate := range map[string]func(*Entry){
		"no org":     func(e *Entry) { e.Org = ids.OrgID{} },
		"no id":      func(e *Entry) { e.ID = ids.UUID{} },
		"bad kind":   func(e *Entry) { e.Kind = "Audit" },
		"flat kind":  func(e *Entry) { e.Kind = "audit" },
		"no actor":   func(e *Entry) { e.Actor = Actor{} },
		"long actor": func(e *Entry) { e.Actor.Type = string(make([]byte, 33)) },
	} {
		e := entry(t, 1)
		mutate(&e)
		if err := e.Validate(); !errors.Is(err, ErrInvalidEntry) {
			t.Errorf("%s: accepted", name)
		}
	}
}

func chain(t *testing.T, n int) ([]Link, []Entry) {
	t.Helper()
	var links []Link
	var entries []Entry
	seq, head := int64(0), GenesisHash
	for i := 1; i <= n; i++ {
		e := entry(t, i)
		l, err := Next(seq, head, e)
		if err != nil {
			t.Fatal(err)
		}
		links, entries = append(links, l), append(entries, e)
		seq, head = l.Seq, l.EntryHash
	}
	return links, entries
}

func verify(links []Link, entries []Entry) error {
	v := NewVerifier()
	for i := range links {
		if err := v.Add(links[i], entries[i]); err != nil {
			return err
		}
	}
	return nil
}

func TestVerifierAcceptsIntactChain(t *testing.T) {
	links, entries := chain(t, 5)
	if err := verify(links, entries); err != nil {
		t.Fatal(err)
	}
}

func TestT029_VerifierDetectsTampering(t *testing.T) {
	cases := map[string]func(l []Link, e []Entry) ([]Link, []Entry){
		"edited body": func(l []Link, e []Entry) ([]Link, []Entry) {
			e[2].Body = []byte(`{"n":999,"note":"test"}`)
			return l, e
		},
		"edited kind": func(l []Link, e []Entry) ([]Link, []Entry) { e[1].Kind = "audit.other"; return l, e },
		"edited ts": func(l []Link, e []Entry) ([]Link, []Entry) {
			e[3].OccurredAt = e[3].OccurredAt.Add(time.Microsecond)
			return l, e
		},
		"deleted entry": func(l []Link, e []Entry) ([]Link, []Entry) {
			return append(l[:2:2], l[3:]...), append(e[:2:2], e[3:]...)
		},
		"swapped entries": func(l []Link, e []Entry) ([]Link, []Entry) { e[1], e[2] = e[2], e[1]; return l, e },
		"other org": func(l []Link, e []Entry) ([]Link, []Entry) {
			e[0].Org = ids.MustParse[ids.Org]("01920000-0000-7000-8000-00000000000b")
			return l, e
		},
		"rehashed link without prev": func(l []Link, e []Entry) ([]Link, []Entry) {
			// An insider rewrites entry 2 and recomputes only its own hash.
			e[1].Body = []byte(`{"n":42,"note":"test"}`)
			c, _ := e[1].Canonical(2)
			l[1].EntryHash = LinkHash(l[1].PrevHash, c)
			return l, e
		},
	}
	for name, tamper := range cases {
		links, entries := chain(t, 5)
		l, e := tamper(links, entries)
		if err := verify(l, e); !errors.Is(err, ErrChainBroken) {
			t.Errorf("%s: not detected (err %v)", name, err)
		}
	}
}

func TestNextRejectsBadHead(t *testing.T) {
	if _, err := Next(0, []byte{1}, entry(t, 1)); err == nil {
		t.Fatal("short head hash accepted")
	}
	if _, err := entry(t, 1).Canonical(0); err == nil {
		t.Fatal("seq 0 accepted")
	}
}
