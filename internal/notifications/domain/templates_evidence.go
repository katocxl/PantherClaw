// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

// evidenceTemplates are the evidence-integrity notification types (G0 M7
// design decision 8, HR-194). Like every template they render only codes
// and fixed text (HR-158).
var evidenceTemplates = []Template{
	{
		Type: "security.evidence_integrity_failed", Severity: Critical, Params: []string{"check", "reason"},
		Title: "The PantherClaw evidence ledger failed an integrity check",
		Body: "The {check} of this organization's evidence ledger failed ({reason}): a ledger entry, its chain link, " +
			"a tile or a checkpoint does not match. Checkpoints are stopped until an operator investigates; receipts " +
			"are still written and chained.",
	},
}

func init() { templates = append(templates, evidenceTemplates...) }
