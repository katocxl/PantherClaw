// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

import (
	"errors"
	"testing"
)

// TestHR034_ApprovalTemplatesMayNamePrerequisiteFacts (G0 M5 part 2,
// decision 9): an approval template may show facts.<name> of a fact the
// definition requires, as a readable name beside the stable id; any other
// fact is refused, and a dedupe key never uses a fact.
func TestHR034_ApprovalTemplatesMayNamePrerequisiteFacts(t *testing.T) {
	p := refundPackage()
	create(p).Approval.Fields = append(create(p).Approval.Fields, "facts.payments.charge.refundable")
	create(p).Approval.Title = "Refund {params.amount} (refundable: {facts.payments.charge.refundable})"
	if err := p.Validate(); err != nil {
		t.Fatalf("a prerequisite fact in the template: %v", err)
	}
	for name, mutate := range map[string]func(*Package){
		"an unrequired fact": func(p *Package) { create(p).Approval.Fields = []string{"facts.customer.name"} },
		"a fact in the title": func(p *Package) {
			create(p).Approval.Title = "Refund {facts.customer.name}"
		},
		"a dedupe key on a fact": func(p *Package) {
			create(p).Dedupe = []string{"target.id", "facts.payments.charge.refundable"}
		},
	} {
		p := refundPackage()
		mutate(p)
		if err := p.Validate(); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: %v, want ErrInvalid", name, err)
		}
	}
}
