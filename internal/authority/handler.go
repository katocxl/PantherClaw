// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package authority

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"strings"

	"connectrpc.com/connect/v2"

	"github.com/katocxl/pantherclaw/internal/authority/domain"
	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/rpc"
)

type gatewayKey struct{}

// WithGateway returns ctx carrying the authenticated gateway.
func WithGateway(ctx context.Context, gw Gateway) context.Context {
	return context.WithValue(ctx, gatewayKey{}, gw)
}

// GatewayFrom returns the authenticated gateway, if any.
func GatewayFrom(ctx context.Context) (Gateway, bool) {
	gw, ok := ctx.Value(gatewayKey{}).(Gateway)
	return gw, ok && gw.ID != "" && !gw.Org.IsZero()
}

// DevGatewayAuthenticator authenticates the single development gateway by a
// static bearer token (only its SHA-256 is held). DEVELOPMENT ONLY: it is a
// stand-in for gateway mTLS with org binding (M6, HR-020). The org comes from
// configuration, never from the request.
func DevGatewayAuthenticator(tokenSHA256 [sha256.Size]byte, gw Gateway) rpc.Authenticator {
	return func(ctx context.Context, info *connect.CallInfo, spec connect.Spec) (context.Context, error) {
		if !strings.HasPrefix(spec.Procedure, "/"+pantherclawv1connect.AuthorityServiceName+"/") {
			return nil, connect.NewError(connect.CodePermissionDenied, "permission denied")
		}
		token, ok := strings.CutPrefix(info.RequestHeader().Get("Authorization"), "Bearer ")
		if !ok || token == "" {
			return nil, connect.NewError(connect.CodeUnauthenticated, "gateway credentials required")
		}
		got := sha256.Sum256([]byte(token))
		if subtle.ConstantTimeCompare(got[:], tokenSHA256[:]) != 1 {
			return nil, connect.NewError(connect.CodeUnauthenticated, "invalid gateway credentials")
		}
		return WithGateway(ctx, gw), nil
	}
}

// Handler serves AuthorityService.
type Handler struct {
	pantherclawv1connect.UnimplementedAuthorityServiceHandler
	svc *Service
}

// NewHandler returns the RPC handler for svc.
func NewHandler(svc *Service) *Handler { return &Handler{svc: svc} }

func gateway(ctx context.Context) (Gateway, error) {
	gw, ok := GatewayFrom(ctx)
	if !ok {
		return Gateway{}, connect.NewError(connect.CodeUnauthenticated, "gateway credentials required")
	}
	return gw, nil
}

var decisionToProto = map[domain.Decision]pantherclawv1.Decision{
	domain.Allow:                pantherclawv1.Decision_DECISION_ALLOW,
	domain.AllowWithObligations: pantherclawv1.Decision_DECISION_ALLOW_WITH_OBLIGATIONS,
	domain.RequireApproval:      pantherclawv1.Decision_DECISION_REQUIRE_APPROVAL,
	domain.RequireStepUp:        pantherclawv1.Decision_DECISION_REQUIRE_STEP_UP,
	domain.Deny:                 pantherclawv1.Decision_DECISION_DENY,
	domain.CannotAuthorize:      pantherclawv1.Decision_DECISION_CANNOT_AUTHORIZE,
}

// Authorize implements AuthorityServiceHandler.
func (h *Handler) Authorize(ctx context.Context, req *pantherclawv1.AuthorizeRequest) (*pantherclawv1.AuthorizeResponse, error) {
	gw, err := gateway(ctx)
	if err != nil {
		return nil, err
	}
	res, err := h.svc.Authorize(ctx, gw, req.GetActionIr())
	if err != nil {
		return nil, err
	}
	out := &pantherclawv1.AuthorizeResponse{
		Decision: decisionToProto[res.Decision], ActionHash: res.ActionHash,
		Permit: res.Permit, Epoch: res.Epoch, Receipt: res.Receipt,
	}
	if !res.TransactionID.IsZero() {
		out.TransactionId = res.TransactionID.String()
	}
	if res.Permit != "" {
		out.PermitId = res.PermitID.String()
	}
	for _, r := range res.Reasons {
		out.Reasons = append(out.Reasons, &pantherclawv1.Reason{Code: r.Code, Check: r.Check, Detail: r.Detail, Decisive: r.Decisive})
	}
	return out, nil
}

// BeginDispatch implements AuthorityServiceHandler.
func (h *Handler) BeginDispatch(ctx context.Context, req *pantherclawv1.BeginDispatchRequest) (*pantherclawv1.BeginDispatchResponse, error) {
	gw, err := gateway(ctx)
	if err != nil {
		return nil, err
	}
	id, err := ids.ParseUUID(req.GetPermitId())
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, "invalid permit id")
	}
	if err := h.svc.BeginDispatch(ctx, gw, id, req.GetEpoch()); err != nil {
		return nil, err
	}
	return &pantherclawv1.BeginDispatchResponse{}, nil
}

var outcomeFromProto = map[pantherclawv1.Outcome]Outcome{
	pantherclawv1.Outcome_OUTCOME_ACCEPTED: Accepted,
	pantherclawv1.Outcome_OUTCOME_FAILED:   Failed,
	pantherclawv1.Outcome_OUTCOME_UNKNOWN:  Unknown,
}

// RecordExecution implements AuthorityServiceHandler.
func (h *Handler) RecordExecution(ctx context.Context, req *pantherclawv1.RecordExecutionRequest) (*pantherclawv1.RecordExecutionResponse, error) {
	gw, err := gateway(ctx)
	if err != nil {
		return nil, err
	}
	id, err := ids.ParseUUID(req.GetPermitId())
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, "invalid permit id")
	}
	outcome, ok := outcomeFromProto[req.GetOutcome()]
	if !ok {
		return nil, connect.NewError(connect.CodeInvalidArgument, "invalid outcome")
	}
	receipt, err := h.svc.RecordExecution(ctx, gw, Execution{
		Permit: id, Outcome: outcome, TargetStatus: req.GetTargetStatus(),
		ResponseDigest: req.GetResponseDigest(), DispatchMS: req.GetDispatchMs(),
	})
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.RecordExecutionResponse{Receipt: receipt}, nil
}
