// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package finalize_test

import (
	"context"
	"testing"

	"github.com/katocxl/pantherclaw/internal/authority/finalize"
	"github.com/katocxl/pantherclaw/internal/authority/pipeline"
	"github.com/katocxl/pantherclaw/internal/authority/pipeline/pipelinetest"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// snapshotWorld hands out the world as a snapshot Reader that counts its
// lookups.
type snapshotWorld struct {
	*pipelinetest.World
	taken, lookups int
}

func (s *snapshotWorld) Snapshot(ctx context.Context, _ ids.OrgID, fn func(context.Context, pipeline.Reader) error) error {
	s.taken++
	return fn(ctx, &countingReader{World: s.World, n: &s.lookups})
}

type countingReader struct {
	*pipelinetest.World
	n *int
}

func (c *countingReader) Lookup(ctx context.Context, org ids.OrgID, run, action ids.UUID) (*finalize.Stored, error) {
	*c.n++
	return c.World.Lookup(ctx, org, run, action)
}

// storeWithoutLookup is the world as a Store whose Lookup must not be used.
type storeWithoutLookup struct {
	finalize.Store
	t *testing.T
}

func (s storeWithoutLookup) Lookup(context.Context, ids.OrgID, ids.UUID, ids.UUID) (*finalize.Stored, error) {
	s.t.Error("the stored transaction was looked up outside the evaluation's snapshot")
	return nil, nil //nolint:nilnil // never reached in a passing test
}

// TestAuthorizeLooksUpInTheEvaluationsSnapshot: the stored transaction is
// read in the snapshot the pipeline evaluates on, a repeat is answered
// from it without an evaluation, and the result carries the receipt that
// was recorded without reading it back.
func TestAuthorizeLooksUpInTheEvaluationsSnapshot(t *testing.T) {
	s, _, run := scenario(t)
	snap := &snapshotWorld{World: s.W}
	s.Authority.Pipeline = &pipeline.Pipeline{Reader: snap}
	s.Authority.Store = storeWithoutLookup{Store: s.W, t: t}

	act := ids.NewV7()
	req := s.Request(run, act, "create_refund", pipelinetest.Refund("ch_1", "30.00"))
	first := s.Authorize(req)
	stored, err := s.W.Lookup(context.Background(), s.Org, run, act)
	if err != nil || stored == nil {
		t.Fatalf("stored: %v %v", stored, err)
	}
	if first.Permit == "" || first.Receipt == "" || first.Receipt != stored.Receipt {
		t.Fatalf("the result's receipt %q, recorded %q", first.Receipt, stored.Receipt)
	}
	again := s.Authorize(req)
	if !again.Repeat || again.Receipt != stored.Receipt {
		t.Fatalf("repeat: %+v", again)
	}
	if snap.taken != 2 || snap.lookups != 2 {
		t.Fatalf("%d snapshots and %d lookups for two requests", snap.taken, snap.lookups)
	}
}
