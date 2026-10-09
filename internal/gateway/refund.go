// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package gateway

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"connectrpc.com/connect/v2"

	"github.com/katocxl/pantherclaw/internal/actionir"
	"github.com/katocxl/pantherclaw/internal/gateway/control"
	pb "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	"github.com/katocxl/pantherclaw/internal/identity/pap"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
)

// mockPayments pins the reviewed meaning of the single route: the refund
// definition of the reference package (packages/mock-payments; a test keeps
// the digest equal to the package's).
var mockPayments = actionir.Definition{
	Package: "pc.mock-payments", Version: "1.0.0",
	Digest: "sha256:9ebb4b465342ac90911d1ea4c9ed1d5ac7e356e9742d17938f99076bb836678d",
}

var chargePattern = regexp.MustCompile(`^ch_[A-Za-z0-9]{1,64}$`)

// Gateway serves the walking-skeleton route.
type Gateway struct {
	org         string
	run         []func(ctx context.Context) error
	containment Containment
	config      Configuration
	broker      *Broker
	authority   pantherclawv1connect.AuthorityServiceClient
	permits     *permitVerifier
	egress      *http.Client
	target      *url.URL
	publicURL   string
	nonces      nonces
	log         *slog.Logger
}

// Handler returns the gateway's HTTP handler.
func (g *Gateway) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/refunds", g.refund)
	return mux
}

type refundRequest struct {
	Charge   string `json:"charge"`
	Amount   string `json:"amount"`
	Currency string `json:"currency"`
	Reason   string `json:"reason"`
}

// result is the gateway's answer to the agent.
type result struct {
	Error         string         `json:"error,omitempty"`
	Decision      string         `json:"decision,omitempty"`
	Reasons       []string       `json:"reasons,omitempty"`
	TransactionID string         `json:"transaction_id,omitempty"`
	Outcome       string         `json:"outcome,omitempty"`
	TargetStatus  int            `json:"target_status,omitzero"`
	Receipt       string         `json:"receipt,omitempty"`
	Response      jsontext.Value `json:"response,omitempty"`
}

func reply(w http.ResponseWriter, status int, r result) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.MarshalWrite(w, r)
}

// timings feeds the Server-Timing header used by the latency measurements.
type timings struct{ start, mark time.Time }

func (t *timings) lap(w http.ResponseWriter, name string) {
	now := time.Now()
	w.Header().Add("Server-Timing", fmt.Sprintf("%s;dur=%.3f", name, float64(now.Sub(t.mark).Microseconds())/1000))
	t.mark = now
}

// refuseContained answers when containment forbids dispatch (HR-010): a
// stale view or a revoked gateway cannot enforce (503); the kill switch is
// a decision of the org (403).
func refuseContained(w http.ResponseWriter, err error) {
	status := http.StatusServiceUnavailable
	if errors.Is(err, control.ErrKillSwitch) {
		status = http.StatusForbidden
	}
	reply(w, status, result{Error: err.Error()})
}

func (g *Gateway) refund(w http.ResponseWriter, r *http.Request) {
	t := timings{start: time.Now(), mark: time.Now()}
	ctx := r.Context()
	if _, err := g.containment.Check(); err != nil {
		refuseContained(w, err)
		return
	}
	// The raw body is hashed before anything parses it (HR-091).
	body, err := io.ReadAll(io.LimitReader(r.Body, 64<<10+1))
	if err != nil || len(body) > 64<<10 {
		reply(w, http.StatusRequestEntityTooLarge, result{Error: "body_too_large"})
		return
	}
	sum := sha256.Sum256(body)
	token, hasToken := strings.CutPrefix(r.Header.Get("Authorization"), "PAP ")
	creds := &pb.WorkloadCredentials{
		WorkloadToken: token, Proof: r.Header.Get(HeaderProof), BodySha256: sum[:], Htm: r.Method,
		Htu: g.publicURL + r.URL.Path, ClientAddress: clientAddress(r),
	}
	switch {
	case creds.Proof == "":
		g.refusePAP(ctx, w, pap.CodeUseNonce, "")
		return
	case !hasToken:
		g.reportUnknown(ctx, w, r, creds)
		return
	}
	instance, env, ok := tokenSubject(token)
	if !ok {
		g.refusePAP(ctx, w, pap.CodeInvalidToken, "")
		return
	}
	run, err1 := ids.ParseUUID(r.Header.Get(HeaderRunID))
	act, err2 := ids.ParseUUID(r.Header.Get(HeaderActionID))
	if err1 != nil || err2 != nil {
		reply(w, http.StatusBadRequest, result{Error: "run_and_action_ids_required"})
		return
	}
	var in refundRequest
	if err := json.Unmarshal(body, &in, json.RejectUnknownMembers(true)); err != nil || !chargePattern.MatchString(in.Charge) {
		reply(w, http.StatusBadRequest, result{Error: "invalid_request"})
		return
	}
	params, err := json.Marshal(actionir.RefundParams{Amount: actionir.Amount{Value: in.Amount, Currency: in.Currency}, Reason: in.Reason})
	if err != nil {
		reply(w, http.StatusBadRequest, result{Error: "invalid_request"})
		return
	}
	p, err := actionir.Encode(actionir.ActionIR{
		V: actionir.Version, Org: g.org, Env: env, RunID: run.String(), ActionID: act.String(), AgentInstance: instance,
		Operation: actionir.OpRefundCreate, Definition: mockPayments, Channel: "http", Route: "payments-refund",
		Target: actionir.Target{Type: "payments.charge", ID: in.Charge}, Params: params,
	})
	if err == nil {
		_, _, err = actionir.Refund(p.Action)
	}
	if err != nil {
		reply(w, http.StatusBadRequest, result{Error: "cannot_authorize", Decision: "CANNOT_AUTHORIZE"})
		return
	}
	t.lap(w, "build")

	res, err := g.authority.Authorize(ctx, &pb.AuthorizeRequest{ActionIr: p.Canonical, Workload: creds})
	t.lap(w, "authz")
	if err != nil {
		g.log.ErrorContext(ctx, "gateway.authority_unavailable", pclog.Err(err))
		reply(w, http.StatusServiceUnavailable, result{Error: "authority_unavailable"})
		return
	}
	g.nonces.set(res.GetNonce(), time.Time{})
	if n := res.GetNonce(); n != "" {
		w.Header().Set(HeaderNonce, n)
	}
	if rs := res.GetReasons(); res.GetDecision() == pb.Decision_DECISION_CANNOT_AUTHORIZE && len(rs) > 0 &&
		rs[0].GetCode() == "IDENTITY_UNVERIFIED" {
		// The workload could not be verified: a PAP-Error, so it can retry
		// with a fresh nonce or token (PAP-1 §12).
		g.refusePAP(ctx, w, pap.Code(rs[0].GetDetail()), res.GetNonce())
		return
	}
	if res.GetDecision() != pb.Decision_DECISION_ALLOW {
		reasons := make([]string, 0, len(res.GetReasons()))
		for _, rs := range res.GetReasons() {
			reasons = append(reasons, rs.GetCode())
		}
		reply(w, http.StatusForbidden, result{
			Decision: strings.TrimPrefix(res.GetDecision().String(), "DECISION_"), Reasons: reasons, TransactionID: res.GetTransactionId(),
		})
		return
	}
	if res.GetPermit() == "" {
		// A retried action gets its stored decision, never a second permit (HR-005).
		reply(w, http.StatusConflict, result{Error: "duplicate_action", Decision: "ALLOW", TransactionID: res.GetTransactionId()})
		return
	}
	want := permitWant{PermitID: res.GetPermitId(), Txn: res.GetTransactionId(), Act: p.HashHex(), Epoch: res.GetEpoch()}
	if err := g.permits.verify(ctx, res.GetPermit(), want); err != nil || res.GetActionHash() != p.HashHex() {
		g.log.ErrorContext(ctx, "security.permit_rejected", slog.String("transaction_id", res.GetTransactionId()), pclog.Err(err))
		reply(w, http.StatusBadGateway, result{Error: "permit_invalid", TransactionID: res.GetTransactionId()})
		return
	}
	t.lap(w, "verify")
	// Containment may have changed while the Authority decided: a permit
	// from an older epoch, or a view gone stale, dispatches nothing.
	// BeginDispatch stays the authoritative check (HR-001).
	if epoch, err := g.containment.Check(); err != nil {
		refuseContained(w, err)
		return
	} else if want.Epoch < epoch {
		reply(w, http.StatusConflict, result{Error: "dispatch_refused", Reasons: []string{"EPOCH_STALE"}, TransactionID: want.Txn})
		return
	}
	if _, err := g.authority.BeginDispatch(ctx, &pb.BeginDispatchRequest{PermitId: want.PermitID, Epoch: want.Epoch}); err != nil {
		reply(w, http.StatusConflict, result{Error: "dispatch_refused", Reasons: []string{connect.CodeOf(err).String()}, TransactionID: want.Txn})
		return
	}
	t.lap(w, "begin")

	// Committed: the agent going away must not stop dispatch or recording.
	ctx = context.WithoutCancel(ctx)
	o := g.dispatch(ctx, want.Txn, p.Action)
	t.lap(w, "target")
	rec, err := g.authority.RecordExecution(ctx, &pb.RecordExecutionRequest{
		PermitId: want.PermitID, Outcome: o.outcome, TargetStatus: int32(o.status), //nolint:gosec // G115: HTTP status ≤ 599
		ResponseDigest: o.digest, DispatchMs: int32(min(o.elapsed.Milliseconds(), 600000)), //nolint:gosec // G115: clamped
	})
	t.lap(w, "record")
	out := result{
		TransactionID: want.Txn, Outcome: strings.TrimPrefix(o.outcome.String(), "OUTCOME_"), TargetStatus: o.status,
		Receipt: rec.GetReceipt(), Response: o.body,
	}
	if err != nil {
		// The sweeper marks the permit UNKNOWN later; the reservation is held.
		g.log.ErrorContext(ctx, "gateway.outcome_not_recorded", slog.String("transaction_id", want.Txn), pclog.Err(err))
		out.Error = "outcome_not_recorded"
	}
	w.Header().Add("Server-Timing", fmt.Sprintf("total;dur=%.3f", float64(time.Since(t.start).Microseconds())/1000))
	switch {
	case err != nil:
		reply(w, http.StatusBadGateway, out)
	case o.outcome == pb.Outcome_OUTCOME_ACCEPTED:
		reply(w, http.StatusOK, out)
	case o.outcome == pb.Outcome_OUTCOME_FAILED:
		reply(w, http.StatusBadGateway, out)
	default:
		reply(w, http.StatusGatewayTimeout, out)
	}
}

// targetRefund is the outbound body, rebuilt from ActionIR (HR-075).
type targetRefund struct {
	Charge   string `json:"charge"`
	Amount   string `json:"amount"`
	Currency string `json:"currency"`
	Reason   string `json:"reason"`
}

type dispatchResult struct {
	outcome pb.Outcome
	status  int
	digest  []byte
	body    jsontext.Value
	elapsed time.Duration
}

// dispatch sends the re-serialized request with an idempotency key derived
// from the transaction id (HR-008) and classifies the outcome: 2xx accepted,
// 4xx or a failed dial failed, anything else unknown (never released).
func (g *Gateway) dispatch(ctx context.Context, txn string, a actionir.ActionIR) dispatchResult {
	start := time.Now()
	rp, _, err := actionir.Refund(a)
	if err != nil {
		return dispatchResult{outcome: pb.Outcome_OUTCOME_FAILED}
	}
	b, err := json.Marshal(targetRefund{Charge: a.Target.ID, Amount: rp.Amount.Value, Currency: rp.Amount.Currency, Reason: rp.Reason})
	if err != nil {
		return dispatchResult{outcome: pb.Outcome_OUTCOME_FAILED}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, g.target.JoinPath("v1", "refunds").String(), bytes.NewReader(b))
	if err != nil {
		return dispatchResult{outcome: pb.Outcome_OUTCOME_FAILED}
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Idempotency-Key", "pc-"+txn)
	req.Header.Set("User-Agent", "pantherclaw-gateway")
	resp, err := g.egress.Do(req)
	if err != nil {
		var op *net.OpError
		if errors.As(err, &op) && op.Op == "dial" {
			// No connection, so nothing was sent.
			return dispatchResult{outcome: pb.Outcome_OUTCOME_FAILED, elapsed: time.Since(start)}
		}
		return dispatchResult{outcome: pb.Outcome_OUTCOME_UNKNOWN, elapsed: time.Since(start)}
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	sum := sha256.Sum256(raw)
	d := dispatchResult{status: resp.StatusCode, digest: sum[:], elapsed: time.Since(start)}
	if v := jsontext.Value(raw); len(raw) <= 64<<10 && v.IsValid() {
		d.body = v
	}
	switch {
	case resp.StatusCode >= 200 && resp.StatusCode < 300:
		d.outcome = pb.Outcome_OUTCOME_ACCEPTED
	case resp.StatusCode >= 400 && resp.StatusCode < 500:
		d.outcome = pb.Outcome_OUTCOME_FAILED
	default:
		d.outcome = pb.Outcome_OUTCOME_UNKNOWN
	}
	return d
}
