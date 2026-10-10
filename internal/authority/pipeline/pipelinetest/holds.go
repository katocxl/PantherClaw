// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pipelinetest

import (
	"context"
	"time"

	"github.com/katocxl/pantherclaw/internal/actionir"
	apdomain "github.com/katocxl/pantherclaw/internal/approvals/domain"
	"github.com/katocxl/pantherclaw/internal/authority/pipeline"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// holdKey names a transaction by its run and action.
type holdKey struct{ run, action ids.UUID }

// holdState is the world's approval requests and settings (G0 M5 part 2).
type holdState struct {
	latest   map[holdKey]*pipeline.HoldRequest
	variants []apdomain.VariantLine
	approved []apdomain.ContextLine
	settings pipeline.HoldSettings
}

func (w *World) holds() *holdState {
	if w.hold == nil {
		w.hold = &holdState{latest: map[holdKey]*pipeline.HoldRequest{}}
	}
	return w.hold
}

// SetHold makes h the latest approval request of (run, action); nil removes
// it.
func (w *World) SetHold(run, action ids.UUID, h *pipeline.HoldRequest) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if h == nil {
		delete(w.holds().latest, holdKey{run, action})
		return
	}
	c := *h
	w.holds().latest[holdKey{run, action}] = &c
}

// SetVariants sets what Variants returns.
func (w *World) SetVariants(v []apdomain.VariantLine, approved []apdomain.ContextLine) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.holds().variants, w.holds().approved = v, approved
}

// SetHoldSettings sets the org's hold settings.
func (w *World) SetHoldSettings(s pipeline.HoldSettings) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.holds().settings = s
}

// Hold implements pipeline.Reader.
func (w *World) Hold(_ context.Context, _ ids.OrgID, run, action ids.UUID) (*pipeline.HoldRequest, error) {
	if err := w.fail("Hold"); err != nil {
		return nil, err
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if h, ok := w.holds().latest[holdKey{run, action}]; ok {
		c := *h
		return &c, nil
	}
	return nil, nil
}

// Variants implements pipeline.Reader.
func (w *World) Variants(context.Context, ids.OrgID, [32]byte, string, actionir.Target, time.Time) (
	[]apdomain.VariantLine, []apdomain.ContextLine, error,
) {
	if err := w.fail("Variants"); err != nil {
		return nil, nil, err
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.holds().variants, w.holds().approved, nil
}

// HoldSettings implements pipeline.Reader.
func (w *World) HoldSettings(context.Context, ids.OrgID) (pipeline.HoldSettings, error) {
	if err := w.fail("HoldSettings"); err != nil {
		return pipeline.HoldSettings{}, err
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.holds().settings, nil
}
