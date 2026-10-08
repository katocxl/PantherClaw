// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package log

import (
	"context"
	"log/slog"
	"slices"
)

type ctxKey struct{}

// WithAttrs returns a context whose log records carry attrs (for example
// request_id and org_id set by an RPC interceptor). Later values for the same
// key are appended, not merged; set each key once per request.
func WithAttrs(ctx context.Context, attrs ...slog.Attr) context.Context {
	prev, _ := ctx.Value(ctxKey{}).([]slog.Attr)
	return context.WithValue(ctx, ctxKey{}, append(slices.Clip(prev), attrs...))
}

// AttrsFrom returns the attributes stored by WithAttrs.
func AttrsFrom(ctx context.Context) []slog.Attr {
	attrs, _ := ctx.Value(ctxKey{}).([]slog.Attr)
	return attrs
}

// contextHandler adds context attributes to each record.
type contextHandler struct {
	inner   slog.Handler
	extract []func(context.Context) []slog.Attr
}

func (h *contextHandler) Enabled(ctx context.Context, l slog.Level) bool {
	return h.inner.Enabled(ctx, l)
}

func (h *contextHandler) Handle(ctx context.Context, r slog.Record) error {
	if ctx != nil {
		r.AddAttrs(AttrsFrom(ctx)...)
		for _, f := range h.extract {
			r.AddAttrs(f(ctx)...)
		}
	}
	return h.inner.Handle(ctx, r)
}

func (h *contextHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &contextHandler{inner: h.inner.WithAttrs(attrs), extract: h.extract}
}

func (h *contextHandler) WithGroup(name string) slog.Handler {
	return &contextHandler{inner: h.inner.WithGroup(name), extract: h.extract}
}
