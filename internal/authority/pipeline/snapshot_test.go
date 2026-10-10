// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pipeline_test

import (
	"context"
	"testing"

	adomain "github.com/katocxl/pantherclaw/internal/authority/domain"
	"github.com/katocxl/pantherclaw/internal/authority/pipeline"
	"github.com/katocxl/pantherclaw/internal/authority/pipeline/pipelinetest"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// snapshots is a Snapshotter whose own reads all fail: only the snapshot's
// Reader (the fixture's world) answers.
type snapshots struct {
	*pipelinetest.World
	inner *pipelinetest.World
	taken int
}

func (s *snapshots) Snapshot(ctx context.Context, _ ids.OrgID, fn func(context.Context, pipeline.Reader) error) error {
	s.taken++
	return fn(ctx, s.inner)
}

// TestEvaluateReadsOneSnapshot: with a Snapshotter, one evaluation takes
// one snapshot and makes every read through it.
func TestEvaluateReadsOneSnapshot(t *testing.T) {
	f := newFx(t)
	outer := pipelinetest.New(org, f.pkg, now)
	for _, m := range []string{"Containment", "Definition", "Policy", "Run", "Agent", "Chain", "Envelopes", "Facts", "Usage", "Claim", "Connection"} {
		outer.Fail[m] = true
	}
	s := &snapshots{World: outer, inner: f.w}
	f.p = &pipeline.Pipeline{Reader: s}
	expect(t, f.call(f.run, "create_refund", refund("ch_1", "30.00")), adomain.Allow, pipeline.ReasonGrantCovers)
	if s.taken != 1 {
		t.Fatalf("%d snapshots for one evaluation", s.taken)
	}
}
