// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain_test

import (
	"encoding/json/jsontext"
	"errors"
	"testing"

	"github.com/katocxl/pantherclaw/internal/approvals/domain"
	defs "github.com/katocxl/pantherclaw/internal/definitions/domain"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

func refundValues(t testing.TB, d *defs.Definition, raw string) defs.Values {
	t.Helper()
	v, err := d.DecodeParams(jsontext.Value(raw))
	if err != nil {
		t.Fatal(err)
	}
	return v
}

// TestHR172_ANarrowerProposalOnlyNarrowsMaterialParameters (F147): an
// amount no larger in the same currency is narrower; a larger amount,
// another currency, another enum value or no change at all is refused.
func TestHR172_ANarrowerProposalOnlyNarrowsMaterialParameters(t *testing.T) {
	d := refundDefinition(t)
	held := refundValues(t, d, `{"amount":{"value":"125.00","currency":"USD"},"reason":"duplicate"}`)
	if err := domain.CheckNarrower(d, held, refundValues(t, d, `{"amount":{"value":"40.00","currency":"USD"},"reason":"duplicate"}`)); err != nil {
		t.Fatalf("a smaller refund: %v", err)
	}
	for name, raw := range map[string]string{
		"a larger amount":  `{"amount":{"value":"125.01","currency":"USD"},"reason":"duplicate"}`,
		"another currency": `{"amount":{"value":"40.00","currency":"EUR"},"reason":"duplicate"}`,
		"another reason":   `{"amount":{"value":"40.00","currency":"USD"},"reason":"fraudulent"}`,
		"the same action":  `{"amount":{"value":"125.00","currency":"USD"},"reason":"duplicate"}`,
		"a missing reason": `{"amount":{"value":"40.00","currency":"USD"}}`,
	} {
		v, err := d.DecodeParams(jsontext.Value(raw))
		if err != nil {
			continue // undecodable is refused before narrowing
		}
		if err := domain.CheckNarrower(d, held, v); !errors.Is(err, domain.ErrNotNarrower) {
			t.Errorf("%s: %v, want NOT_NARROWER", name, err)
		}
	}
}

// FuzzNarrowerProposal: whatever amount is proposed, CheckNarrower accepts
// it only when it is no larger than the held one in the same currency.
func FuzzNarrowerProposal(f *testing.F) {
	d := refundDefinition(f)
	held := refundValues(f, d, `{"amount":{"value":"125.00","currency":"USD"},"reason":"duplicate"}`)
	for _, s := range []string{"40.00", "125.00", "125.01", "0.00", "999999.99"} {
		f.Add(s, "USD")
	}
	f.Fuzz(func(t *testing.T, amount, currency string) {
		v, err := d.DecodeParams(jsontext.Value(`{"amount":{"value":` + jsontext.Value(`"`+amount+`"`).String() +
			`,"currency":"` + currency + `"},"reason":"duplicate"}`))
		if err != nil {
			return
		}
		err = domain.CheckNarrower(d, held, v)
		smaller := v["amount"].Money.Currency == held["amount"].Money.Currency &&
			v["amount"].Money.Amount.Cmp(held["amount"].Money.Amount) < 0
		if (err == nil) != smaller {
			t.Fatalf("%s %s: err=%v, smaller=%v", amount, currency, err, smaller)
		}
	})
}

// TestHR172_RespondingNeedsTheRoleButNoKey: declining or asking needs the
// requirement's role on the scope path and no exclusion, but neither a
// security key nor the cooldowns, which guard approvals only.
func TestHR172_RespondingNeedsTheRoleButNoKey(t *testing.T) {
	c := ctx()
	p := veteran()
	p.Credentials, p.JoinedAt, p.Bindings[0].CreatedAt, p.Bindings[0].SelfGranted = nil, now, now, true
	if ok, code := domain.MayRespond(approver(2, false), p, c); !ok {
		t.Fatalf("a new approver without a key may not decline: %s", code)
	}
	p.Bindings = nil
	if ok, _ := domain.MayRespond(approver(1, false), p, c); ok {
		t.Fatal("a person without the role may respond")
	}
	launcher := veteran()
	c.Run.Launcher = userP(launcher.UserID)
	if ok, code := domain.MayRespond(approver(1, false), launcher, c); ok || code != domain.IneligibleLauncher {
		t.Fatalf("the launcher may respond: %v %s", ok, code)
	}
	stepUp := domain.Requirement{Kind: domain.KindStepUp, Subject: domain.SubjectLauncher, Method: domain.MethodWebAuthn}
	if ok, _ := domain.MayRespond(stepUp, launcher, c); !ok {
		t.Fatal("the step-up's subject may decline it")
	}
	if ok, _ := domain.MayRespond(stepUp, domain.Person{UserID: ids.NewV7(), Enabled: true}, c); ok {
		t.Fatal("someone else may decline a step-up")
	}
}
