// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package log

import "log/slog"

// Redacted is the text that replaces secret and sensitive values in every
// rendering: logs, fmt verbs, JSON and text encodings.
const Redacted = "[REDACTED]"

// Secret holds a credential, key or token. It renders as [REDACTED] in logs,
// fmt output and JSON, and the value is kept behind a pointer so that even
// printing a struct with an unexported Secret field cannot reveal it.
// Call Reveal only at the point of use.
type Secret[T any] struct {
	p *T
}

// NewSecret wraps v.
func NewSecret[T any](v T) Secret[T] { return Secret[T]{p: &v} }

// Reveal returns the wrapped value (the zero value if none is set).
func (s Secret[T]) Reveal() T {
	if s.p == nil {
		var zero T
		return zero
	}
	return *s.p
}

// IsSet reports whether a value was wrapped.
func (s Secret[T]) IsSet() bool { return s.p != nil }

// LogValue implements slog.LogValuer.
func (Secret[T]) LogValue() slog.Value { return slog.StringValue(Redacted) }

// String implements fmt.Stringer.
func (Secret[T]) String() string { return Redacted }

// GoString implements fmt.GoStringer (the %#v verb).
func (Secret[T]) GoString() string { return Redacted }

// MarshalText implements encoding.TextMarshaler so JSON encoders emit
// "[REDACTED]" instead of the value.
func (Secret[T]) MarshalText() ([]byte, error) { return []byte(Redacted), nil }

// Sensitive holds personal or customer data that is legitimate to process but
// must not appear in operational logs (SB-4, SB-9). It renders like Secret.
type Sensitive[T any] struct {
	p *T
}

// NewSensitive wraps v.
func NewSensitive[T any](v T) Sensitive[T] { return Sensitive[T]{p: &v} }

// Reveal returns the wrapped value (the zero value if none is set).
func (s Sensitive[T]) Reveal() T {
	if s.p == nil {
		var zero T
		return zero
	}
	return *s.p
}

// LogValue implements slog.LogValuer.
func (Sensitive[T]) LogValue() slog.Value { return slog.StringValue(Redacted) }

// String implements fmt.Stringer.
func (Sensitive[T]) String() string { return Redacted }

// GoString implements fmt.GoStringer.
func (Sensitive[T]) GoString() string { return Redacted }

// MarshalText implements encoding.TextMarshaler.
func (Sensitive[T]) MarshalText() ([]byte, error) { return []byte(Redacted), nil }
