// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app_test

import (
	"strings"
	"testing"

	authnapp "github.com/katocxl/pantherclaw/internal/authn/app"
	"github.com/katocxl/pantherclaw/internal/platform/clock"
)

func TestHR154_CounterMustMoveForward(t *testing.T) {
	for _, tc := range []struct {
		stored, received uint32
		ok               bool
	}{
		{0, 0, true},  // synced passkey: never counts
		{0, 1, true},  // first use of a counting key
		{5, 6, true},  // moved forward
		{5, 9, true},  // skipped values are fine
		{5, 5, false}, // stayed: a clone used the same value
		{5, 4, false}, // went back
		{5, 0, false}, // a counting key reporting 0
		{0xfffffffe, 0xffffffff, true},
	} {
		if got := authnapp.CounterOK(tc.stored, tc.received); got != tc.ok {
			t.Errorf("CounterOK(%d, %d) = %v, want %v", tc.stored, tc.received, got, tc.ok)
		}
	}
}

func TestHR153_RelyingPartyConfiguration(t *testing.T) {
	ok := []authnapp.WebAuthnConfig{
		{RPID: "pc.example.test", PublicURL: "https://pc.example.test"},
		{RPID: "example.test", PublicURL: "https://pc.example.test"}, // a parent domain
		{RPID: "localhost", PublicURL: "http://localhost:8080"},
	}
	for _, c := range ok {
		if _, err := authnapp.NewWebAuthn(nil, c, nil, clock.System{}, nil); err != nil {
			t.Errorf("%+v: %v", c, err)
		}
	}
	bad := []authnapp.WebAuthnConfig{
		{RPID: "127.0.0.1", PublicURL: "http://127.0.0.1:8080"},        // IP addresses are not RP ids
		{RPID: "localhost", PublicURL: "http://127.0.0.1:8080"},        // host is an IP
		{RPID: "pc.example.test", PublicURL: "http://pc.example.test"}, // http beyond localhost
		{RPID: "other.test", PublicURL: "https://pc.example.test"},     // not the host or a parent
		{RPID: "xample.test", PublicURL: "https://pc.example.test"},    // a suffix but not a parent domain
		{RPID: "pc.example.test", PublicURL: "https://pc.example.test/app"},
		{RPID: "", PublicURL: "https://pc.example.test"},
	}
	for _, c := range bad {
		if _, err := authnapp.NewWebAuthn(nil, c, nil, clock.System{}, nil); err == nil {
			t.Errorf("%+v was accepted", c)
		}
	}
}

func TestCredentialNames(t *testing.T) {
	for _, n := range []string{"YubiKey 5", "Laptop passkey", "clé", strings.Repeat("k", 64)} {
		if !authnapp.ValidCredentialName(n) {
			t.Errorf("%q refused", n)
		}
	}
	for _, n := range []string{"", " padded", "bidi" + string(rune(0x202e)) + "name", "new\nline", strings.Repeat("k", 65), "nul\x00"} {
		if authnapp.ValidCredentialName(n) {
			t.Errorf("%q accepted", n)
		}
	}
}
