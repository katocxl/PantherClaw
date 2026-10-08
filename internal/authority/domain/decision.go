// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package domain holds the Transaction Authority's pure decision rules. In
// the M1.5 walking skeleton the only authority is a hard-coded development
// grant; the full ten-step pipeline arrives in M4 (ARCHITECTURE §6.1).
package domain

import (
	"errors"

	"github.com/katocxl/pantherclaw/internal/actionir"
	"github.com/katocxl/pantherclaw/internal/platform/money"
)

// Decision is an authorization decision (PAP-1 §7.1).
type Decision string

// The six decisions.
const (
	Allow                Decision = "ALLOW"
	AllowWithObligations Decision = "ALLOW_WITH_OBLIGATIONS"
	RequireApproval      Decision = "REQUIRE_APPROVAL"
	RequireStepUp        Decision = "REQUIRE_STEP_UP"
	Deny                 Decision = "DENY"
	CannotAuthorize      Decision = "CANNOT_AUTHORIZE"
)

// Permits reports whether the decision allows dispatch (subject to the
// permit and the BeginDispatch commit point).
func (d Decision) Permits() bool { return d == Allow || d == AllowWithObligations }

// Reason explains one checklist outcome.
type Reason struct {
	Code     string `json:"code"`
	Check    string `json:"check"`
	Detail   string `json:"detail,omitempty"`
	Decisive bool   `json:"decisive"`
}

// Stable reason codes used by the walking skeleton.
const (
	ReasonAllowedByGrant      = "ALLOWED_BY_GRANT"
	ReasonAmbiguousInput      = "AMBIGUOUS_INPUT"
	ReasonNoGrant             = "NO_GRANT"
	ReasonGrantAmountExceeded = "GRANT_AMOUNT_EXCEEDED"
	ReasonGrantCurrency       = "GRANT_CURRENCY_MISMATCH"
	ReasonOrgMismatch         = "ORG_MISMATCH"
	ReasonKillSwitch          = "KILL_SWITCH_ENGAGED"
	ReasonContainmentUnknown  = "CONTAINMENT_UNKNOWN"
	ReasonBudgetExhausted     = "BUDGET_EXHAUSTED"
	ReasonBudgetUnavailable   = "BUDGET_UNAVAILABLE"
	ReasonActionTampered      = "ACTION_TAMPERED"
	ReasonDuplicateRequest    = "DUPLICATE_REQUEST"
)

// Outcome is the result of evaluating one action before finalization.
type Outcome struct {
	Decision Decision
	Reasons  []Reason
	Amount   money.Money
}

// Decisive returns the decisive reason code.
func (o Outcome) Decisive() string {
	for _, r := range o.Reasons {
		if r.Decisive {
			return r.Code
		}
	}
	if len(o.Reasons) > 0 {
		return o.Reasons[0].Code
	}
	return ""
}

func single(d Decision, code, check, detail string) Outcome {
	return Outcome{Decision: d, Reasons: []Reason{{Code: code, Check: check, Detail: detail, Decisive: true}}}
}

// DevGrant is the M1.5 hard-coded grant: one operation, a per-action cap
// and the budget that reservations draw from. Development only.
type DevGrant struct {
	Name         string
	Operation    string
	MaxPerAction money.Money
	BudgetName   string
}

// Evaluate checks the action against the grant. Ambiguity is
// CANNOT_AUTHORIZE, exceeding the grant is DENY (prohibitions win).
func (g DevGrant) Evaluate(p actionir.Parsed) Outcome {
	if p.Action.Operation != g.Operation {
		return single(Deny, ReasonNoGrant, "authority", "no grant covers this operation")
	}
	_, amount, err := actionir.Refund(p.Action)
	if err != nil {
		if errors.Is(err, actionir.ErrAmbiguous) {
			return single(CannotAuthorize, ReasonAmbiguousInput, "exact_meaning", "parameters are ambiguous or unsupported")
		}
		return single(CannotAuthorize, ReasonAmbiguousInput, "exact_meaning", "parameters could not be evaluated")
	}
	cmp, err := amount.Cmp(g.MaxPerAction)
	if err != nil {
		return single(Deny, ReasonGrantCurrency, "authority", "currency not covered by the grant")
	}
	if cmp > 0 {
		return single(Deny, ReasonGrantAmountExceeded, "authority", "amount exceeds the grant's per-action maximum")
	}
	o := single(Allow, ReasonAllowedByGrant, "authority", "")
	o.Amount = amount
	return o
}
