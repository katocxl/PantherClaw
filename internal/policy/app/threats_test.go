// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/katocxl/pantherclaw/internal/actionir"
	"github.com/katocxl/pantherclaw/internal/policy/domain"
)

// TestT018_PolicyCannotFailOpen: a prohibition is never skipped by lexical
// amount comparison or by a swallowed error.
func TestT018_PolicyCannotFailOpen(t *testing.T) {
	f := newFixture(t)
	c, err := f.compile(refundRule("cap", domain.Forbid, `action.params.amount > money("100.00", "USD")`))
	if err != nil {
		t.Fatal(err)
	}
	// "1000.00" < "100.00" as strings; as money it is larger.
	if out := f.eval(c, f.refund("1000.00", "duplicate"), DefaultBudget); out.Verdict != domain.VerdictDeny {
		t.Fatalf("1000.00 USD against a 100.00 cap: %s", out.Verdict)
	}
	// An error inside the prohibition (another currency) denies.
	eur, err := f.mapper.MCP(context.Background(), tc, "create_refund",
		[]byte(`{"charge":"ch_1","amount":"5.00","currency":"EUR","reason":"duplicate"}`))
	if err != nil {
		t.Fatal(err)
	}
	if out := f.eval(c, eur.Action, DefaultBudget); out.Verdict != domain.VerdictDeny {
		t.Fatalf("a currency the prohibition cannot compare: %s", out.Verdict)
	}
}

// TestT020_ParserDifferentialsNeverReachPolicy: inputs another parser could
// read differently are refused before any rule runs.
func TestT020_ParserDifferentialsNeverReachPolicy(t *testing.T) {
	f := newFixture(t)
	for name, args := range map[string]string{
		"duplicate amount":         `{"charge":"ch_1","amount":"1.00","amount":"5000.00","currency":"USD","reason":"duplicate"}`,
		"escaped duplicate":        `{"charge":"ch_1","amount":"1.00","amo\u0075nt":"5000.00","currency":"USD","reason":"duplicate"}`,
		"number amount":            `{"charge":"ch_1","amount":5000,"currency":"USD","reason":"duplicate"}`,
		"lowercase currency":       `{"charge":"ch_1","amount":"1.00","currency":"usd","reason":"duplicate"}`,
		"fullwidth digits":         `{"charge":"ch_1","amount":"` + string(rune(0xff15)) + `.00","currency":"USD","reason":"duplicate"}`,
		"confusable charge":        `{"charge":"ch_` + string(rune(0x0391)) + `","amount":"1.00","currency":"USD","reason":"duplicate"}`,
		"shadow field":             `{"charge":"ch_1","amount":"1.00","currency":"USD","reason":"duplicate","amount_cents":500000}`,
		"trailing second document": `{"charge":"ch_1","amount":"1.00","currency":"USD","reason":"duplicate"} {"amount":"5000.00"}`,
	} {
		if _, err := f.mapper.MCP(context.Background(), tc, "create_refund", []byte(args)); !errors.Is(err, actionir.ErrAmbiguous) {
			t.Errorf("%s: err = %v, want ErrAmbiguous (CANNOT_AUTHORIZE)", name, err)
		}
	}
}

// TestT023_PolicyWorkIsBounded: oversized input, expensive rules and budget
// exhaustion all stop with CANNOT_AUTHORIZE or a refused publication.
func TestT023_PolicyWorkIsBounded(t *testing.T) {
	f := newFixture(t)
	huge := `{"charge":"ch_1","x":"` + strings.Repeat("a", actionir.MaxBytes) + `"}`
	if _, err := f.mapper.MCP(context.Background(), tc, "create_refund", []byte(huge)); !errors.Is(err, actionir.ErrAmbiguous) {
		t.Fatalf("oversized input: %v", err)
	}
	expensive := refundRule("slow", domain.Forbid,
		`action.destinations.all(a, action.destinations.all(b, action.destinations.all(c, a.id == b.id)))`)
	if _, err := f.compile(expensive); !errors.Is(err, domain.ErrInvalid) {
		t.Fatalf("an unbounded rule must be refused at publication: %v", err)
	}
	c, _ := f.compile(referenceRules()...)
	if out := f.eval(c, f.refund("30.00", "duplicate"), 2); out.Verdict != domain.VerdictCannotAuthorize {
		t.Fatalf("budget exhaustion: %s", out.Verdict)
	}
}
