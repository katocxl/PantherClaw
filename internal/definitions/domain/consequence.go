// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

import (
	"regexp"

	"github.com/katocxl/pantherclaw/internal/actionir"
)

// ConsequenceRule is a reviewed, bounded downstream consequence of an
// operation under named conditions (F405, ConsequenceIR). It predicts a
// possible effect; it never proves one happened.
type ConsequenceRule struct {
	ID            string      `json:"id"`
	Operation     string      `json:"operation"`
	When          string      `json:"when"`
	RequiresFacts []string    `json:"requires_facts"`
	Consequence   Consequence `json:"consequence"`
	ValidUntil    string      `json:"valid_until"`
}

// Consequence is the predicted downstream effect.
type Consequence struct {
	Operation   string `json:"operation"`
	Effect      string `json:"effect"`
	Description string `json:"description"`
}

var idRe = regexp.MustCompile(`^[a-z][a-z0-9-]{0,63}$`)

// validateConsequences checks the consequence rules against the package's
// operations.
func (p *Package) validateConsequences(ops map[string]*Definition) error {
	ids := map[string]bool{}
	for _, c := range p.Consequences {
		if err := c.validate(ops); err != nil {
			return err
		}
		if ids[c.ID] {
			return invalid("duplicate consequence rule %s", c.ID)
		}
		ids[c.ID] = true
	}
	return nil
}

func (c ConsequenceRule) validate(ops map[string]*Definition) error {
	switch {
	case !idRe.MatchString(c.ID):
		return invalid("consequence id %q", c.ID)
	case ops[c.Operation] == nil:
		return invalid("consequence %s: operation %s is not defined in this package", c.ID, c.Operation)
	case !actionir.ValidOperation(c.Consequence.Operation) || !kindRe.MatchString(c.Consequence.Effect):
		return invalid("consequence %s: needs a consequence operation and effect", c.ID)
	case len(c.RequiresFacts) == 0 || len(c.RequiresFacts) > maxItems:
		return invalid("consequence %s: a consequence needs 1..%d verified facts (no invented causality)", c.ID, maxItems)
	}
	for _, f := range c.RequiresFacts {
		if !kindRe.MatchString(f) {
			return invalid("consequence %s: fact %q", c.ID, f)
		}
	}
	if err := expr("consequence "+c.ID+".when", c.When, true); err != nil {
		return err
	}
	if err := text("consequence "+c.ID+".description", c.Consequence.Description); err != nil {
		return err
	}
	_, err := parseDay("consequence "+c.ID+".valid_until", c.ValidUntil)
	return err
}
