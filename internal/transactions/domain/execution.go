// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

// ExecutionState is where an action stands between its decision and its
// effect (F471–F479). It is derived from the records, never stored, and
// always shown beside the effect state: permission is not dispatch,
// dispatch is not success, and success is not a verified effect.
type ExecutionState string

// Execution states.
const (
	Requested  ExecutionState = "REQUESTED"
	Blocked    ExecutionState = "BLOCKED"
	Waiting    ExecutionState = "WAITING"
	Authorized ExecutionState = "AUTHORIZED"
	Dispatched ExecutionState = "DISPATCHED"
	Accepted   ExecutionState = "ACCEPTED"
	Failed     ExecutionState = "FAILED"
	Canceled   ExecutionState = "CANCELLED" //nolint:misspell // the state's name, British spelling as in ARCHITECTURE §6.2
)

// Record is what the execution state is derived from: the transaction's
// latest decision and reason, its permit's state (empty when it has none)
// and its attempt's outcome (empty when none was recorded).
type Record struct {
	Decision    string
	Reason      string
	PermitState string
	Outcome     string
}

// heldEnds are the reasons a held action ended without running: declined,
// expired or replaced by a narrower proposal (G0 M5 part 2).
var heldEnds = map[string]bool{"APPROVAL_DECLINED": true, "APPROVAL_EXPIRED": true, "NARROWER_PROPOSED": true}

// Execution derives the execution state of r (G0 M7 design decision 7).
func Execution(r Record) ExecutionState {
	switch r.Decision {
	case "":
		return Requested
	case "REQUIRE_APPROVAL", "REQUIRE_STEP_UP":
		return Waiting
	case "DENY":
		if heldEnds[r.Reason] {
			return Canceled // a hold that ended: nothing was sent
		}
		return Blocked
	case "CANNOT_AUTHORIZE":
		return Blocked
	}
	switch r.PermitState {
	case "", "ISSUED":
		return Authorized
	case "RELEASED":
		return Canceled // the permit expired unused: nothing was sent
	case "DISPATCHING", "UNKNOWN":
		return Dispatched
	}
	switch r.Outcome {
	case "accepted":
		return Accepted
	case "failed":
		return Failed
	}
	// DISPATCHED with an unknown or delegated outcome: sent (or allowed to
	// the agent itself), and no answer establishes more.
	return Dispatched
}
