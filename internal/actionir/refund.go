// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package actionir

import (
	"slices"

	"github.com/katocxl/pantherclaw/internal/platform/money"
)

// OpRefundCreate is the walking-skeleton operation (BUILD_GUIDE §8 M1.5).
const OpRefundCreate = "payments.refund.create"

// Amount is a material money parameter: a decimal string, never a JSON number.
type Amount struct {
	Value    string `json:"value"`
	Currency string `json:"currency"`
}

// RefundParams are the parameters of payments.refund.create.
type RefundParams struct {
	Amount Amount `json:"amount"`
	Reason string `json:"reason"`
}

// RefundReasons is the closed set of refund reasons (mock-payments package).
var RefundReasons = []string{"duplicate", "fraudulent", "requested_by_customer"}

// Refund decodes and validates the parameters of a refund action. A missing
// or unsupported value is ambiguous, never defaulted (HR-103).
func Refund(a ActionIR) (RefundParams, money.Money, error) {
	if a.Operation != OpRefundCreate {
		return RefundParams{}, money.Money{}, ambiguous("operation %q is not %s", a.Operation, OpRefundCreate)
	}
	var p RefundParams
	if err := a.DecodeParams(&p); err != nil {
		return RefundParams{}, money.Money{}, err
	}
	m, err := money.ParseMoney(p.Amount.Value, p.Amount.Currency)
	if err != nil {
		return RefundParams{}, money.Money{}, ambiguous("amount: %v", err)
	}
	if m.Amount.Sign() <= 0 {
		return RefundParams{}, money.Money{}, ambiguous("amount must be positive")
	}
	if !slices.Contains(RefundReasons, p.Reason) {
		return RefundParams{}, money.Money{}, ambiguous("unsupported refund reason")
	}
	return p, m, nil
}
