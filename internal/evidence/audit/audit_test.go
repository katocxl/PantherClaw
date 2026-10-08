// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package audit

import (
	"errors"
	"strings"
	"testing"

	"github.com/katocxl/pantherclaw/internal/evidence/domain"
)

func valid() Event {
	return Event{
		Name: "licence.installed", Actor: domain.Actor{Type: "user", ID: "u-1"}, Outcome: Success,
		ReasonCode: "LICENCE_VALID", Object: &Object{Type: "licence", ID: "lic-1"},
		Details: map[string]string{"edition": "team"},
	}
}

func TestEventValidation(t *testing.T) {
	if err := valid().validate(); err != nil {
		t.Fatal(err)
	}
	cases := map[string]func(*Event){
		"flat name":    func(e *Event) { e.Name = "installed" },
		"upper name":   func(e *Event) { e.Name = "Licence.Installed" },
		"bad outcome":  func(e *Event) { e.Outcome = "ok" },
		"bad reason":   func(e *Event) { e.ReasonCode = "lower" },
		"empty object": func(e *Event) { e.Object = &Object{} },
		"secret key":   func(e *Event) { e.Details = map[string]string{"client_secret": "x"} },
		"token key":    func(e *Event) { e.Details = map[string]string{"api_token": "x"} },
		"bad key":      func(e *Event) { e.Details = map[string]string{"Bad-Key": "x"} },
		"long value":   func(e *Event) { e.Details = map[string]string{"note": strings.Repeat("x", 513)} },
		"too many":     func(e *Event) { e.Details = manyDetails(17) },
	}
	for name, mutate := range cases {
		e := valid()
		mutate(&e)
		if err := e.validate(); !errors.Is(err, ErrInvalidEvent) {
			t.Errorf("%s: accepted (err %v)", name, err)
		}
	}
}

func manyDetails(n int) map[string]string {
	m := map[string]string{}
	for i := range n {
		m["k"+strings.Repeat("a", i+1)] = "v"
	}
	return m
}
