// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package finalize

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/v2"
	"fmt"
	"strconv"
	"time"

	adomain "github.com/katocxl/pantherclaw/internal/authority/domain"
	"github.com/katocxl/pantherclaw/internal/authority/pipeline"
	evdomain "github.com/katocxl/pantherclaw/internal/evidence/domain"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	pdomain "github.com/katocxl/pantherclaw/internal/policy/domain"
)

// JOSE types of Authority-signed artifacts (PAP-1 §7.2, §9.1).
const (
	TypePermit          = "pap-permit+jwt"
	TypeDecisionReceipt = "pap-decision+jwt"
	// MaxReceiptBytes is the size the receipts table accepts.
	MaxReceiptBytes = 64 << 10
)

// DecisionReceipt is the signed record of one evaluation (PAP-1 §9.1). It
// records the decision, never an effect: dispatch and effects have their
// own receipts (invariants 7 and 11). Agent-supplied text never appears in
// it (HR-023).
type DecisionReceipt struct {
	Iss string      `json:"iss"`
	Jti string      `json:"jti"`
	Iat int64       `json:"iat"`
	Pap DecisionPAP `json:"pap"`
}

// DecisionPAP is the receipt's claim set.
type DecisionPAP struct {
	V           int                           `json:"v"`
	Kind        string                        `json:"kind"`
	Org         string                        `json:"org"`
	Txn         string                        `json:"txn"`
	Evaluation  int                           `json:"evaluation"`
	Run         string                        `json:"run"`
	Action      string                        `json:"action"`
	Act         string                        `json:"act"`
	Effective   string                        `json:"effective,omitzero"`
	Decision    adomain.Decision              `json:"decision"`
	Checklist   []pipeline.Item               `json:"checklist"`
	Omitted     int                           `json:"omitted,omitzero"`
	Obligations []pdomain.Obligation          `json:"obligations,omitzero"`
	Approvals   []pdomain.ApprovalRequirement `json:"approvals,omitzero"`
	StepUps     []pdomain.StepUpRequirement   `json:"step_ups,omitzero"`
	Basis       pipeline.Basis                `json:"basis"`
	BasisDigest string                        `json:"basis_digest"`
	Identity    pipeline.IdentitySummary      `json:"identity"`
	Budgets     []BudgetState                 `json:"budgets,omitzero"`
	Gateway     string                        `json:"gateway"`
	// Monitor marks a hypothetical decision in monitor mode (HR-184): it
	// prevented nothing; Connection is the connection the action named.
	Monitor    bool   `json:"monitor,omitzero"`
	Connection string `json:"connection,omitzero"`
	// DestinationClass is the connection's class, from its record (HR-079).
	DestinationClass string `json:"destination_class,omitzero"`
	Simulated        bool   `json:"simulated"`
}

// receipt builds, fits and signs the decision receipt of one evaluation.
func (a *Authority) receipt(gw Gateway, ev *pipeline.Evaluation, txn ids.UUID, evaluation int, budgets []BudgetState) (Receipt, error) {
	pap := DecisionPAP{
		V: 1, Kind: "decision", Org: gw.Org.String(), Txn: txn.String(), Evaluation: evaluation,
		Run: ev.RunID.String(), Action: ev.ActionID.String(), Act: ev.ActionHash, Decision: ev.Decision,
		Checklist: ev.Checklist, Obligations: ev.Obligations, Approvals: ev.Approvals, StepUps: ev.StepUps,
		Basis: ev.Basis, BasisDigest: ev.Basis.Digest(), Identity: ev.Identity, Budgets: budgets, Gateway: gw.ID,
		Monitor: ev.MonitorPermit(),
	}
	if ev.EffectiveHash != ev.ActionHash {
		pap.Effective = ev.EffectiveHash
	}
	if ev.Connection != nil {
		pap.Connection, pap.DestinationClass = ev.Connection.ID.String(), ev.Connection.DestinationClass
	}
	r := DecisionReceipt{Iss: a.issuer(), Jti: txn.String() + "/" + strconv.Itoa(evaluation), Iat: ev.Now.Unix(), Pap: pap}
	payload, err := fit(r)
	if err != nil {
		return Receipt{}, err
	}
	jws, err := a.Receipts.Sign(TypeDecisionReceipt, payload)
	if err != nil {
		return Receipt{}, err
	}
	digest := sha256.Sum256([]byte(jws))
	entry := map[string]string{
		"txn": txn.String(), "evaluation": strconv.Itoa(evaluation), "decision": string(ev.Decision),
		"act": ev.ActionHash, "reason": ev.Decisive().Code, "receipt_sha256": hex.EncodeToString(digest[:]),
	}
	if pap.Monitor {
		entry["monitor"] = "true"
	}
	body, err := evdomain.CanonicalBody(entry)
	if err != nil {
		return Receipt{}, err
	}
	return Receipt{JWS: jws, Body: body}, nil
}

// fit marshals r, dropping passed and not-applicable checklist items (then
// any item but the decisive one) until the signed receipt stays well under
// MaxReceiptBytes; it records how many items it left out.
func fit(r DecisionReceipt) ([]byte, error) {
	const budget = MaxReceiptBytes / 2 // the JWS is base64 and signed
	for range 3 {
		b, err := json.Marshal(r, json.Deterministic(true))
		if err != nil {
			return nil, err
		}
		if len(b) <= budget {
			return b, nil
		}
		kept := r.Pap.Checklist[:0:0]
		for i, it := range r.Pap.Checklist {
			if i == 0 || (it.Status != pipeline.StatusPassed && it.Status != pipeline.StatusNotApplicable && len(kept) < 64) {
				kept = append(kept, it)
			}
		}
		r.Pap.Omitted += len(r.Pap.Checklist) - len(kept)
		r.Pap.Checklist = kept
		if len(kept) <= 1 {
			r.Pap.Obligations, r.Pap.Budgets = nil, nil
		}
	}
	return nil, fmt.Errorf("finalize: the decision receipt does not fit %d bytes", MaxReceiptBytes)
}

type permitClaims struct {
	Iss string    `json:"iss"`
	Aud string    `json:"aud"`
	Jti string    `json:"jti"`
	Iat int64     `json:"iat"`
	Exp int64     `json:"exp"`
	Pap permitPAP `json:"pap"`
}

type permitPAP struct {
	V     int    `json:"v"`
	Org   string `json:"org"`
	Txn   string `json:"txn"`
	Act   string `json:"act"`
	Epoch int64  `json:"epoch"`
}

// permit signs the single-use permit (HR-009). It binds the effective
// action: what the gateway may dispatch after any clamping (F107). A
// monitor-mode permit binds the requested action, which monitor mode
// dispatches unchanged (HR-184).
func (a *Authority) permit(gw Gateway, ev *pipeline.Evaluation, txn ids.UUID) (*PermitWrite, error) {
	id := ids.NewV7()
	exp := ev.Now.Add(a.ttl())
	act := ev.EffectiveHash
	if ev.MonitorPermit() {
		act = ev.ActionHash
	}
	b, err := json.Marshal(permitClaims{
		Iss: a.issuer(), Aud: "gw:" + gw.ID, Jti: id.String(), Iat: ev.Now.Unix(), Exp: exp.Unix(),
		Pap: permitPAP{V: 1, Org: gw.Org.String(), Txn: txn.String(), Act: act, Epoch: ev.Epoch},
	})
	if err != nil {
		return nil, err
	}
	jws, err := a.Permits.Sign(TypePermit, b)
	if err != nil {
		return nil, err
	}
	return &PermitWrite{ID: id, JWS: jws, GatewayID: gw.ID, Epoch: ev.Epoch, ExpiresAt: exp}, nil
}

func (a *Authority) issuer() string {
	if a.Issuer == "" {
		return "pantherclaw"
	}
	return a.Issuer
}

// TypeExecutionReceipt is the JOSE type of an execution receipt (PAP-1
// §7.4).
const TypeExecutionReceipt = "pap-execution+jwt"

// Execution is a gateway's report of one dispatch attempt.
type Execution struct {
	Permit  ids.UUID
	Outcome Outcome
	// TargetStatus is the target's HTTP status (0: none was received).
	TargetStatus int32
	// ResponseDigest is the SHA-256 of the target's response body (empty
	// when there was none).
	ResponseDigest []byte
	// DispatchMS is how long the dispatch took (-1: unknown).
	DispatchMS int32
}

// executionReceipt signs what the gateway reported about a dispatch. It
// records the attempt, never a verified effect (invariant 11): effect
// receipts come with reconciliation (M7).
func (a *Authority) executionReceipt(gw Gateway, e Execution, x Executed, now time.Time) (Receipt, error) {
	txn := x.Transaction
	pap := map[string]any{
		"v": 1, "kind": "execution", "org": gw.Org.String(), "txn": txn.String(), "permit": e.Permit.String(),
		"outcome": string(e.Outcome), "target_status": e.TargetStatus, "response_digest": hex.EncodeToString(e.ResponseDigest),
		"gateway": gw.ID, "access_mode": x.AccessMode, "simulated": false,
	}
	if x.Monitor {
		pap["monitor"] = true // nothing was prevented (HR-184)
	}
	if x.Connection != nil {
		pap["connection"] = x.Connection.String()
	}
	payload, err := json.Marshal(map[string]any{"iss": a.issuer(), "jti": e.Permit.String(), "iat": now.Unix(), "pap": pap}, json.Deterministic(true))
	if err != nil {
		return Receipt{}, err
	}
	jws, err := a.Receipts.Sign(TypeExecutionReceipt, payload)
	if err != nil {
		return Receipt{}, err
	}
	digest := sha256.Sum256([]byte(jws))
	body, err := evdomain.CanonicalBody(map[string]string{
		"txn": txn.String(), "permit": e.Permit.String(), "outcome": string(e.Outcome),
		"receipt_sha256": hex.EncodeToString(digest[:]),
	})
	if err != nil {
		return Receipt{}, err
	}
	return Receipt{JWS: jws, Body: body}, nil
}
