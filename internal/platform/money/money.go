// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package money

import (
	"errors"
	"fmt"
)

var (
	// ErrUnsupportedCurrency reports a currency code that is not supported.
	// Callers on the authorization path map it to CANNOT_AUTHORIZE (HR-103).
	ErrUnsupportedCurrency = errors.New("money: unsupported currency")
	// ErrCurrencyMismatch reports arithmetic across currencies.
	ErrCurrencyMismatch = errors.New("money: currency mismatch")
	// ErrPrecision reports an amount finer than the currency's minor unit.
	ErrPrecision = errors.New("money: amount finer than the currency minor unit")
)

// Currency is an ISO 4217 alphabetic code.
type Currency string

// minorUnits lists supported ISO 4217 currencies and their minor-unit digits.
// The list is deliberately explicit: an unknown currency is unsupported
// rather than assumed to have two decimals (no defaults, HR-103).
var minorUnits = map[Currency]int{
	"AED": 2, "AUD": 2, "BHD": 3, "BRL": 2, "CAD": 2, "CHF": 2, "CLP": 0, "CNY": 2,
	"CZK": 2, "DKK": 2, "EUR": 2, "GBP": 2, "HKD": 2, "HUF": 2, "IDR": 2, "ILS": 2,
	"INR": 2, "ISK": 0, "JOD": 3, "JPY": 0, "KES": 2, "KRW": 0, "KWD": 3, "MXN": 2,
	"MYR": 2, "NGN": 2, "NOK": 2, "NZD": 2, "OMR": 3, "PHP": 2, "PLN": 2, "QAR": 2,
	"RON": 2, "SAR": 2, "SEK": 2, "SGD": 2, "THB": 2, "TND": 3, "TRY": 2, "TWD": 2,
	"UAH": 2, "UGX": 0, "USD": 2, "VND": 0, "ZAR": 2,
}

// ParseCurrency validates an ISO 4217 code. Lowercase codes are rejected, not
// case-folded (PAP-1 §6: currencies are uppercase).
func ParseCurrency(s string) (Currency, error) {
	c := Currency(s)
	if _, ok := minorUnits[c]; !ok {
		if len(s) > 8 {
			s = s[:8] + "…"
		}
		return "", fmt.Errorf("%w: %q", ErrUnsupportedCurrency, s)
	}
	return c, nil
}

// MinorUnits returns the number of fraction digits of the currency.
func (c Currency) MinorUnits() (int, error) {
	n, ok := minorUnits[c]
	if !ok {
		return 0, fmt.Errorf("%w: %q", ErrUnsupportedCurrency, string(c))
	}
	return n, nil
}

// Money is an amount in a currency.
type Money struct {
	Amount   Decimal
	Currency Currency
}

// New builds Money after checking that the currency is supported and that the
// amount is not finer than the currency's minor unit (USD 85.001 is rejected).
func New(amount Decimal, currency Currency) (Money, error) {
	n, err := currency.MinorUnits()
	if err != nil {
		return Money{}, err
	}
	if amount.Scale() > n {
		return Money{}, fmt.Errorf("%w: %s %s", ErrPrecision, amount, currency)
	}
	return Money{Amount: amount, Currency: currency}, nil
}

// ParseMoney parses an amount string and a currency code.
func ParseMoney(amount, currency string) (Money, error) {
	d, err := Parse(amount)
	if err != nil {
		return Money{}, err
	}
	c, err := ParseCurrency(currency)
	if err != nil {
		return Money{}, err
	}
	return New(d, c)
}

// String formats as "<amount> <currency>" with the currency's minor units.
func (m Money) String() string {
	n, err := m.Currency.MinorUnits()
	if err != nil {
		return m.Amount.String() + " " + string(m.Currency)
	}
	s, err := m.Amount.StringFixed(n)
	if err != nil {
		s = m.Amount.String()
	}
	return s + " " + string(m.Currency)
}

// Add returns m + o; both must have the same currency.
func (m Money) Add(o Money) (Money, error) {
	if m.Currency != o.Currency {
		return Money{}, fmt.Errorf("%w: %s + %s", ErrCurrencyMismatch, m.Currency, o.Currency)
	}
	d, err := m.Amount.Add(o.Amount)
	if err != nil {
		return Money{}, err
	}
	return Money{Amount: d, Currency: m.Currency}, nil
}

// Sub returns m - o; both must have the same currency.
func (m Money) Sub(o Money) (Money, error) {
	if m.Currency != o.Currency {
		return Money{}, fmt.Errorf("%w: %s - %s", ErrCurrencyMismatch, m.Currency, o.Currency)
	}
	d, err := m.Amount.Sub(o.Amount)
	if err != nil {
		return Money{}, err
	}
	return Money{Amount: d, Currency: m.Currency}, nil
}

// Cmp compares m and o; both must have the same currency.
func (m Money) Cmp(o Money) (int, error) {
	if m.Currency != o.Currency {
		return 0, fmt.Errorf("%w: %s vs %s", ErrCurrencyMismatch, m.Currency, o.Currency)
	}
	return m.Amount.Cmp(o.Amount), nil
}
