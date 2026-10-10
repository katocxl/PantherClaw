// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package dispatch

import (
	"context"
	"crypto/sha256"
	"encoding/json/v2"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"

	"connectrpc.com/connect/v2"

	"github.com/katocxl/pantherclaw/internal/actionir"
	defs "github.com/katocxl/pantherclaw/internal/definitions/domain"
	"github.com/katocxl/pantherclaw/internal/gateway/control"
	"github.com/katocxl/pantherclaw/internal/gateway/egress"
	"github.com/katocxl/pantherclaw/internal/gateway/upstream"
	pb "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/platform/httpx"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
)

// sendMCP builds, commits, calls and records an action through a kind-mcp
// connection (G0 M6 design decision 14): the reviewed upstream tool with
// arguments built from the permitted action. BeginDispatch binds the
// canonical {name, arguments} (upstream.Params), whatever protocol version
// and JSON-RPC id carry it. The credential and the action token go on every
// request of the call (discovery, the session's initialize, the call
// itself, answers to the server), within the credential's hosts.
//
// Outcomes: a result is ACCEPTED; a tool error (isError), a JSON-RPC
// error, an input_required result (HR-082) and an HTTP 4xx are FAILED; a
// call that never left the gateway is FAILED; anything after it left
// without an answer is UNKNOWN.
func (e *Engine) sendMCP(ctx context.Context, r Result, conn *control.Connection, def *defs.Definition, a actionir.Parsed, want permitWant,
	t *timer,
) Result {
	tool, args, buildErr := egress.BuildMCP(def, a.Action)
	var params []byte
	if buildErr == nil {
		params, buildErr = upstream.Params(tool, args)
	}
	begin := &pb.BeginDispatchRequest{PermitId: want.PermitID, Epoch: want.Epoch}
	if buildErr == nil {
		sum := sha256.Sum256(params)
		begin.OutboundMethod, begin.OutboundUrl, begin.OutboundBodySha256 = http.MethodPost, conn.GetBaseUrl(), sum[:]
	}
	bd, err := e.authority.BeginDispatch(ctx, begin)
	t.lap("begin")
	if err != nil {
		r.Reasons = append(r.Reasons, strings.ToUpper(connect.CodeOf(err).String()))
		return r.fail(EnforcementFailed, CodeDispatchRefused)
	}
	ctx = context.WithoutCancel(ctx)
	ce, err := e.entry(conn)
	if buildErr == nil && err != nil {
		buildErr = err
	}
	if buildErr != nil {
		e.log.WarnContext(ctx, "gateway.request_not_built", slog.String("transaction_id", want.Txn), pclog.Err(buildErr))
		return e.record(ctx, r, want, pb.Outcome_OUTCOME_FAILED, 0, nil, 0, EnforcementFailed, CodeRequest, t)
	}
	var secret []byte
	if conn.GetAccessMode() == "pantherclaw_held" {
		if secret, err = e.openCredential(conn); err != nil {
			e.log.WarnContext(ctx, "gateway.credential_unavailable", slog.String("transaction_id", want.Txn),
				slog.String("connection_id", conn.GetId()), pclog.Err(err))
			return e.record(ctx, r, want, pb.Outcome_OUTCOME_FAILED, 0, nil, 0, EnforcementFailed, CodeCredential, t)
		}
		defer clear(secret)
	}
	token := bd.GetActionToken()
	decorate := func(req *http.Request) error {
		if token != "" {
			req.Header.Set(HeaderAction, token)
		}
		if secret != nil {
			return placeCredential(conn, req, secret)
		}
		return nil
	}
	start := time.Now()
	res, err := ce.mcp.Call(ctx, tool, args, decorate)
	elapsed := time.Since(start)
	t.lap("target")
	outcome, class, code := classifyMCP(res, err)
	e.breaker.record(ctx, conn, outcome)
	if err != nil {
		e.log.WarnContext(ctx, "gateway.target_error", slog.String("transaction_id", want.Txn), slog.String("outcome", outcome.String()),
			pclog.Err(err))
	}
	var digest []byte
	if body := answerBody(res); body != nil {
		// The digest is of what the server sent; the agent gets it without
		// the credential.
		sum := sha256.Sum256(body)
		digest = sum[:]
		r.Response = &egress.Response{
			Status: res.Status, Body: egress.Redacted(body, secret), ContentType: "application/json",
			RequestID: string(egress.Redacted([]byte(res.RequestID), secret)),
		}
		r.ToolResult = res.Error == nil && !res.InputRequired
	}
	return e.record(ctx, r, want, outcome, res.Status, digest, elapsed, class, code, t)
}

// answerBody is what the server answered: the CallToolResult, an
// input_required result, or the JSON-RPC error.
func answerBody(res upstream.Result) []byte {
	switch {
	case res.Error != nil:
		b, err := json.Marshal(res.Error)
		if err != nil {
			return nil
		}
		return b
	case len(res.Result) > 0:
		return res.Result
	}
	return nil
}

// classifyMCP maps an upstream answer to an outcome.
func classifyMCP(res upstream.Result, err error) (pb.Outcome, Class, string) {
	switch {
	case errors.Is(err, upstream.ErrNotSent):
		var op *net.OpError
		switch {
		case errors.Is(err, httpx.ErrDestinationDenied):
			return pb.Outcome_OUTCOME_FAILED, EnforcementFailed, CodeEgressDenied
		case errors.Is(err, egress.ErrHost):
			return pb.Outcome_OUTCOME_FAILED, EnforcementFailed, CodeRequest
		case errors.As(err, &op) && op.Op == "dial":
			return pb.Outcome_OUTCOME_FAILED, ToolFailed, CodeTargetUnreachable
		}
		return pb.Outcome_OUTCOME_FAILED, ToolFailed, CodeTargetRefused
	case err != nil:
		return pb.Outcome_OUTCOME_UNKNOWN, Uncertain, CodeTargetUncertain
	case res.InputRequired:
		return pb.Outcome_OUTCOME_FAILED, ToolFailed, CodeInputRequired
	case res.Error != nil || (res.Status >= 400 && res.Status < 500):
		return pb.Outcome_OUTCOME_FAILED, ToolFailed, CodeTargetRefused
	case res.Status < 200 || res.Status >= 300 || len(res.Result) == 0:
		return pb.Outcome_OUTCOME_UNKNOWN, Uncertain, CodeTargetUncertain
	case res.IsError:
		return pb.Outcome_OUTCOME_FAILED, ToolFailed, CodeToolError
	}
	return pb.Outcome_OUTCOME_ACCEPTED, "", ""
}
