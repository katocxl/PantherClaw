// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain_test

import (
	"encoding/json/jsontext"
	"errors"
	"strings"
	"testing"

	"github.com/katocxl/pantherclaw/internal/actionir"
	"github.com/katocxl/pantherclaw/internal/definitions/domain"
)

// TestHR102_CommandAndPathValues: a command is material text kept exactly
// as sent, without control (other than tab and newline), format or bidi
// characters; a path is accepted only in its normalized spelling (HR-187).
func TestHR102_CommandAndPathValues(t *testing.T) {
	d := &domain.Definition{Params: map[string]domain.ParamSpec{
		"command": {Type: domain.TypeCommand, Material: true, Required: true, MaxLength: 64},
		"cwd":     {Type: domain.TypePath, Material: true, Required: true},
	}}
	ok := []string{
		`{"command":"git status","cwd":"C:\\Users\\dev\\repo"}`,
		`{"command":"cat <<EOF\n\tx\nEOF","cwd":"/home/dev"}`,
		`{"command":"echo 'é'","cwd":"\\\\server\\share"}`,
	}
	for _, in := range ok {
		vals, err := d.DecodeParams(jsontext.Value(in))
		if err != nil {
			t.Errorf("%s: %v", in, err)
			continue
		}
		raw, err := d.EncodeParams(vals)
		if err != nil {
			t.Errorf("%s: encode: %v", in, err)
			continue
		}
		if again, err := d.DecodeParams(raw); err != nil || again["command"].Str != vals["command"].Str || again["cwd"].Str != vals["cwd"].Str {
			t.Errorf("%s does not round-trip: %v", in, err)
		}
	}
	for name, in := range map[string]string{
		"unnormalized path":  `{"command":"ls","cwd":"c:/Users/dev"}`,
		"relative path":      `{"command":"ls","cwd":"repo"}`,
		"device path":        `{"command":"ls","cwd":"\\\\?\\C:\\x"}`,
		"carriage return":    `{"command":"ls\r","cwd":"/x"}`,
		"escape":             `{"command":"ls\u001b[2J","cwd":"/x"}`,
		"bidi":               `{"command":"ls \u202e","cwd":"/x"}`,
		"too long":           `{"command":"` + strings.Repeat("a", 65) + `","cwd":"/x"}`,
		"command not string": `{"command":["ls"],"cwd":"/x"}`,
	} {
		if _, err := d.DecodeParams(jsontext.Value(in)); !errors.Is(err, actionir.ErrAmbiguous) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// TestCommandAndPathDeclarations: both may be material; a path's
// max_length cannot exceed the path limit, and neither takes a unit,
// currencies, values or a pattern.
func TestCommandAndPathDeclarations(t *testing.T) {
	for name, p := range map[string]domain.ParamSpec{
		"long path":         {Type: domain.TypePath, MaxLength: actionir.MaxPath + 1},
		"command pattern":   {Type: domain.TypeCommand, Pattern: "^ls$"},
		"path unit":         {Type: domain.TypePath, Unit: "bytes"},
		"command values":    {Type: domain.TypeCommand, Values: []string{"ls"}},
		"path currencies":   {Type: domain.TypePath, Currencies: []string{"USD"}},
		"command too large": {Type: domain.TypeCommand, MaxLength: 1 << 20},
	} {
		d := minimal(map[string]domain.ParamSpec{"p": p})
		if err := d.Validate(); !errors.Is(err, domain.ErrInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
	d := minimal(map[string]domain.ParamSpec{
		"p": {Type: domain.TypeCommand, Material: true, MaxLength: 8192},
		"q": {Type: domain.TypePath, Material: true},
	})
	if err := d.Validate(); err != nil {
		t.Fatal(err)
	}
}

// minimal is a valid read definition with params and one hook mapping
// that extracts none of them.
func minimal(params map[string]domain.ParamSpec) *domain.Definition {
	return &domain.Definition{
		Operation: "x.y.read", Summary: "s", Access: domain.AccessRead,
		Target:  domain.TargetSpec{Type: "x.thing", IDPattern: "^a$", Account: domain.PresenceNone},
		Params:  params,
		Effects: []domain.Effect{{Kind: "none", Description: "Reads only"}}, Reversibility: domain.Reversible,
		Retry:     domain.RetrySpec{Safe: true, OnUnknown: domain.OnUnknownFail},
		Assurance: domain.Assurance{Basis: domain.BasisDeclared, ReviewedBy: []string{"me"}, ValidUntil: "2027-01-01"},
		Mappings:  []domain.Mapping{{Channel: domain.ChannelHook, Tool: "x", Route: "x", Extract: domain.Extract{TargetID: "'a'", Params: map[string]string{}}}},
	}
}
