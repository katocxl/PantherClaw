// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package finalize_test

import (
	"testing"

	apdomain "github.com/katocxl/pantherclaw/internal/approvals/domain"
	adomain "github.com/katocxl/pantherclaw/internal/authority/domain"
	"github.com/katocxl/pantherclaw/internal/authority/finalize"
	"github.com/katocxl/pantherclaw/internal/authority/pipeline"
	"github.com/katocxl/pantherclaw/internal/authority/pipeline/pipelinetest"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// TestHR174_AHeldActionReturnsItsWaitHandle: a hold answers with the wait
// handle (the transaction id, PAP-1 §7.1), its state and deadline; a
// decline answers DENY with the DECLINED state and nothing else: never a
// note, an identity or the display.
func TestHR174_AHeldActionReturnsItsWaitHandle(t *testing.T) {
	s, _, run := scenario(t)
	holdOver50(t, s)
	act := ids.NewV7()
	req := s.Request(run, act, "create_refund", pipelinetest.Refund("ch_1", "85.00"))
	held := s.Authorize(req)
	w := held.Wait
	if held.Decision != adomain.RequireApproval || w == nil || w.Handle != held.TransactionID ||
		w.State != apdomain.WaitPending || w.RetryAfter != finalize.DefaultRetryAfter || w.Deadline.IsZero() {
		t.Fatalf("held %s, wait %+v", held.Decision, w)
	}
	if allowed := s.Authorize(s.Request(run, ids.NewV7(), "create_refund", pipelinetest.Refund("ch_1", "30.00"))); allowed.Wait != nil {
		t.Fatalf("an allowed action has a wait handle: %+v", allowed.Wait)
	}

	s.W.SetHold(run, act, &pipeline.HoldRequest{
		ID: ids.NewV7(), State: apdomain.StateDeclined, EndReason: apdomain.EndDeclined, Deadline: w.Deadline,
	})
	declined := s.Authorize(req)
	if declined.Decision != adomain.Deny || declined.Wait == nil || declined.Wait.State != apdomain.WaitDeclined ||
		declined.Wait.Code != apdomain.ReasonApprovalDeclined || declined.Wait.RetryAfter != 0 {
		t.Fatalf("declined %s, wait %+v", declined.Decision, declined.Wait)
	}
	if again := s.Authorize(req); !again.Repeat || again.Decision != adomain.Deny {
		t.Fatalf("a decline is terminal for the action id: %+v", again)
	}
}
