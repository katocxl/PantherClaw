// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package authority

import (
	"google.golang.org/protobuf/types/known/timestamppb"

	apdomain "github.com/katocxl/pantherclaw/internal/approvals/domain"
	"github.com/katocxl/pantherclaw/internal/authority/finalize"
	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
)

var waitStateToProto = map[string]pantherclawv1.WaitState{
	apdomain.WaitPending:           pantherclawv1.WaitState_WAIT_STATE_PENDING,
	apdomain.WaitEvidenceRequested: pantherclawv1.WaitState_WAIT_STATE_EVIDENCE_REQUESTED,
	apdomain.WaitReady:             pantherclawv1.WaitState_WAIT_STATE_READY,
	apdomain.WaitDeclined:          pantherclawv1.WaitState_WAIT_STATE_DECLINED,
	apdomain.WaitNarrowerProposed:  pantherclawv1.WaitState_WAIT_STATE_NARROWER_PROPOSED,
	apdomain.WaitExpired:           pantherclawv1.WaitState_WAIT_STATE_EXPIRED,
	apdomain.WaitSuperseded:        pantherclawv1.WaitState_WAIT_STATE_SUPERSEDED,
	apdomain.WaitInvalidated:       pantherclawv1.WaitState_WAIT_STATE_INVALIDATED,
	apdomain.WaitConsumed:          pantherclawv1.WaitState_WAIT_STATE_CONSUMED,
}

// WaitInfo maps a wait handle to its wire form (PAP-1 §7.1): states,
// codes and times only (HR-174).
func WaitInfo(w *finalize.Wait) *pantherclawv1.WaitInfo {
	if w == nil {
		return nil
	}
	out := &pantherclawv1.WaitInfo{
		Handle: w.Handle.String(), RetryAfterSeconds: int32(w.RetryAfter.Seconds()), State: waitStateToProto[w.State],
		Code: w.Code, ProposedParams: w.ProposedParams,
	}
	if !w.Deadline.IsZero() {
		out.DeadlineTime = timestamppb.New(w.Deadline)
	}
	if w.ConsumeBy != nil {
		out.ConsumeByTime = timestamppb.New(*w.ConsumeBy)
	}
	if w.EvidenceDeadline != nil {
		out.EvidenceDeadlineTime = timestamppb.New(*w.EvidenceDeadline)
	}
	if !w.RequestID.IsZero() {
		out.ApprovalRequestId = w.RequestID.String()
	}
	return out
}
