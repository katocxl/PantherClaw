// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package egress

import (
	"errors"
	"testing"

	"github.com/katocxl/pantherclaw/internal/actionir"
)

// TestHR073_QueryParametersComeOnlyFromTheTemplate: a listing's query is
// built from the reviewed names and the action's canonical values, encoded
// by the gateway; an absent optional param leaves its name out, and a value
// that would carry a control character is refused (G0 M7 design decision 5).
func TestHR073_QueryParametersComeOnlyFromTheTemplate(t *testing.T) {
	p, _ := mock(t)
	list, _ := p.Definition("payments.refund.list")
	recent, _ := p.Definition("payments.refund.recent")
	cases := []struct {
		name   string
		d      string
		target actionir.Target
		params string
		want   string
	}{
		{
			"by charge", "list",
			actionir.Target{Type: "payments.charge", ID: "ch_1"},
			`{}`,
			"https://payments.example.test/v1/refunds?charge=ch_1",
		},
		{
			"next page", "list",
			actionir.Target{Type: "payments.charge", ID: "ch_1"},
			`{"starting_after":"re_0192-ab"}`,
			"https://payments.example.test/v1/refunds?charge=ch_1&starting_after=re_0192-ab",
		},
		{
			"target log", "recent",
			actionir.Target{Type: "pc.connection", ID: "01920000-0000-7000-8000-000000000007"},
			`{"created_gte":"1760097600"}`, "https://payments.example.test/v1/refunds?created_gte=1760097600",
		},
	}
	for _, c := range cases {
		d := list
		if c.d == "recent" {
			d = recent
		}
		a := actionir.ActionIR{Operation: d.Operation, Target: c.target, Params: []byte(c.params)}
		r, err := Build("https://payments.example.test", d, a, txn)
		if err != nil || r.URL.String() != c.want || r.Method != "GET" || r.Body != nil || r.IdempotencyHeader != "" {
			t.Errorf("%s: %v %+v", c.name, err, r)
		}
	}
	// The charge id travels encoded; it can never add a parameter.
	a := actionir.ActionIR{Operation: list.Operation, Target: actionir.Target{Type: "payments.charge", ID: "ch_1&charge=ch_2"}, Params: []byte(`{}`)}
	r, err := Build("https://payments.example.test", list, a, txn)
	if err != nil || r.URL.Query()["charge"][0] != "ch_1&charge=ch_2" || len(r.URL.Query()["charge"]) != 1 {
		t.Fatalf("encoded value: %v %v", err, r.URL)
	}
	a.Target.ID = "ch_1\r\nX: y"
	if _, err := Build("https://payments.example.test", list, a, txn); !errors.Is(err, ErrBuild) {
		t.Fatalf("a control character: %v", err)
	}
}
