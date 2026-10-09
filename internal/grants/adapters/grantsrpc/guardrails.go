// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package grantsrpc

import (
	"context"
	"encoding/json/v2"
	"strings"

	"google.golang.org/protobuf/types/known/durationpb"

	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	"github.com/katocxl/pantherclaw/internal/grants/app"
	"github.com/katocxl/pantherclaw/internal/grants/domain"
	"github.com/katocxl/pantherclaw/internal/platform/page"
)

// Guardrails serves GuardrailService.
type Guardrails struct {
	pantherclawv1connect.UnimplementedGuardrailServiceHandler
	svc *app.Service
}

// NewGuardrails returns the GuardrailService handler.
func NewGuardrails(svc *app.Service) *Guardrails { return &Guardrails{svc: svc} }

var (
	scopeKinds = map[pantherclawv1.GuardrailScopeKind]domain.ScopeKind{
		pantherclawv1.GuardrailScopeKind_GUARDRAIL_SCOPE_KIND_ORG:           domain.ScopeOrg,
		pantherclawv1.GuardrailScopeKind_GUARDRAIL_SCOPE_KIND_BUSINESS_UNIT: domain.ScopeBusinessUnit,
		pantherclawv1.GuardrailScopeKind_GUARDRAIL_SCOPE_KIND_TEAM:          domain.ScopeTeam,
		pantherclawv1.GuardrailScopeKind_GUARDRAIL_SCOPE_KIND_ENVIRONMENT:   domain.ScopeEnvironment,
		pantherclawv1.GuardrailScopeKind_GUARDRAIL_SCOPE_KIND_PRINCIPAL:     domain.ScopePrincipal,
	}
	scopeKindProtos = func() map[domain.ScopeKind]pantherclawv1.GuardrailScopeKind {
		out := map[domain.ScopeKind]pantherclawv1.GuardrailScopeKind{}
		for k, v := range scopeKinds {
			out[v] = k
		}
		return out
	}()
)

// scope decodes a guardrail scope; the proto's own rule already ties the
// kind to an id or a principal.
func scope(s *pantherclawv1.GuardrailScope) (domain.Scope, error) {
	out := domain.Scope{Kind: scopeKinds[s.GetKind()]}
	var err error
	switch out.Kind {
	case domain.ScopeOrg:
	case domain.ScopePrincipal:
		out.Principal, err = principal(s.GetPrincipal())
	case domain.ScopeBusinessUnit, domain.ScopeTeam, domain.ScopeEnvironment:
		out.ID, err = parseID(s.GetId())
	default:
		err = errInvalidID
	}
	return out, err
}

func scopeProto(s domain.Scope) *pantherclawv1.GuardrailScope {
	out := &pantherclawv1.GuardrailScope{Kind: scopeKindProtos[s.Kind]}
	switch s.Kind {
	case domain.ScopeOrg:
	case domain.ScopePrincipal:
		out.Principal = actor(s.Principal)
	case domain.ScopeBusinessUnit, domain.ScopeTeam, domain.ScopeEnvironment:
		out.Id = s.ID.String()
	}
	return out
}

func settings(s *pantherclawv1.GuardrailSettings) domain.Settings {
	var out domain.Settings
	if s == nil {
		return out
	}
	if s.MaxDepth != nil {
		v := int(s.GetMaxDepth())
		out.MaxDepth = &v
	}
	if s.MaxChildren != nil {
		v := int(s.GetMaxChildren())
		out.MaxChildren = &v
	}
	if s.GetMaxRootLifetime() != nil {
		v := s.GetMaxRootLifetime().AsDuration()
		out.MaxRootLifetime = &v
	}
	if s.GetRepeatWindow() != nil {
		v := s.GetRepeatWindow().AsDuration()
		out.RepeatWindow = &v
	}
	return out
}

func settingsProto(s domain.Settings) *pantherclawv1.GuardrailSettings {
	out := &pantherclawv1.GuardrailSettings{}
	if s.MaxDepth != nil {
		v := int32(*s.MaxDepth) //nolint:gosec // 0..4
		out.MaxDepth = &v
	}
	if s.MaxChildren != nil {
		v := int32(*s.MaxChildren) //nolint:gosec // 0..50
		out.MaxChildren = &v
	}
	if s.MaxRootLifetime != nil {
		out.MaxRootLifetime = durationpb.New(*s.MaxRootLifetime)
	}
	if s.RepeatWindow != nil {
		out.RepeatWindow = durationpb.New(*s.RepeatWindow)
	}
	return out
}

type encoded struct{ bounds, requirements, limits []byte }

// encodeTerms returns the canonical documents the server stores.
func encodeTerms(b domain.Bounds, reqs []domain.Requirement, lim domain.Limits) (encoded, error) {
	var e encoded
	var err error
	if e.bounds, err = domain.EncodeBounds(b); err != nil {
		return e, err
	}
	if reqs == nil {
		reqs = []domain.Requirement{}
	}
	if e.requirements, err = json.Marshal(reqs, json.Deterministic(true)); err != nil {
		return e, err
	}
	e.limits, err = json.Marshal(lim, json.Deterministic(true))
	return e, err
}

// changedBy renders a stored "kind:id" author.
func changedBy(s string) *pantherclawv1.Actor {
	kind, id, ok := strings.Cut(s, ":")
	if !ok {
		return nil
	}
	return &pantherclawv1.Actor{Kind: kind, Id: id}
}

// EnvelopeProto renders a guardrail revision.
func EnvelopeProto(e domain.Envelope) (*pantherclawv1.Envelope, error) {
	enc, err := encodeTerms(e.Bounds, e.Requirements, e.Limits)
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.Envelope{
		Id: e.ID.String(), Revision: int32(e.Revision), Scope: scopeProto(e.Scope), Name: e.Name, //nolint:gosec // small
		Bounds: enc.bounds, Requirements: enc.requirements, Limits: enc.limits, Settings: settingsProto(e.Settings),
		MinAttestationLevel: int32(e.MinAttestation), ChangedBy: changedBy(e.ChangedBy), CreateTime: ts(e.RevisedAt), //nolint:gosec // 0..2
	}, nil
}

func (s *Guardrails) put(ctx context.Context, sc domain.Scope, revision int, name string, bounds, reqs, limits []byte,
	set *pantherclawv1.GuardrailSettings, minAtt int32,
) (domain.Envelope, domain.Change, error) {
	t, err := DecodeTerms(bounds, reqs, limits)
	if err != nil {
		return domain.Envelope{}, domain.Change{}, err
	}
	return s.svc.PutEnvelope(ctx, app.EnvelopeRequest{
		Scope: sc, Revision: revision, Name: name, Bounds: t.Bounds, Requirements: t.Requirements, Limits: t.Limits,
		Settings: settings(set), MinAttestation: int(minAtt),
	})
}

// CreateEnvelope implements GuardrailServiceHandler.
func (s *Guardrails) CreateEnvelope(ctx context.Context, req *pantherclawv1.CreateEnvelopeRequest) (*pantherclawv1.CreateEnvelopeResponse, error) {
	sc, err := scope(req.GetScope())
	if err != nil {
		return nil, err
	}
	e, _, err := s.put(ctx, sc, 0, req.GetName(), req.GetBounds(), req.GetRequirements(), req.GetLimits(),
		req.GetSettings(), req.GetMinAttestationLevel())
	if isRevisionChanged(err) {
		return nil, errGuardrailExists
	}
	if err != nil {
		return nil, err
	}
	out, err := EnvelopeProto(e)
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.CreateEnvelopeResponse{Envelope: out}, nil
}

func parseEnvelopeID(s string) (domain.EnvelopeID, error) {
	if _, err := parseID(s); err != nil {
		return domain.EnvelopeID{}, err
	}
	id, err := domain.ParseEnvelopeID(s)
	if err != nil {
		return domain.EnvelopeID{}, errInvalidID
	}
	return id, nil
}

// ReviseEnvelope implements GuardrailServiceHandler. The caller must be
// able to read the guardrail before it can change it.
func (s *Guardrails) ReviseEnvelope(ctx context.Context, req *pantherclawv1.ReviseEnvelopeRequest) (*pantherclawv1.ReviseEnvelopeResponse, error) {
	id, err := parseEnvelopeID(req.GetId())
	if err != nil {
		return nil, err
	}
	cur, err := s.svc.EnvelopeByID(ctx, id, 0)
	if err != nil {
		return nil, err
	}
	e, change, err := s.put(ctx, cur.Scope, int(req.GetRevision()), req.GetName(), req.GetBounds(), req.GetRequirements(),
		req.GetLimits(), req.GetSettings(), req.GetMinAttestationLevel())
	if err != nil {
		return nil, err
	}
	out, err := EnvelopeProto(e)
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.ReviseEnvelopeResponse{Envelope: out, Widens: change.Widens}, nil
}

// GetEnvelope implements GuardrailServiceHandler.
func (s *Guardrails) GetEnvelope(ctx context.Context, req *pantherclawv1.GetEnvelopeRequest) (*pantherclawv1.GetEnvelopeResponse, error) {
	id, err := parseEnvelopeID(req.GetId())
	if err != nil {
		return nil, err
	}
	e, err := s.svc.EnvelopeByID(ctx, id, int(req.GetRevision()))
	if err != nil {
		return nil, err
	}
	out, err := EnvelopeProto(e)
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.GetEnvelopeResponse{Envelope: out}, nil
}

// ListEnvelopes implements GuardrailServiceHandler.
func (s *Guardrails) ListEnvelopes(ctx context.Context, req *pantherclawv1.ListEnvelopesRequest) (*pantherclawv1.ListEnvelopesResponse, error) {
	pr, err := page.Parse(req.GetPageSize(), req.GetPageToken())
	if err != nil {
		return nil, err
	}
	p, err := s.svc.Envelopes(ctx, pr, scopeKinds[req.GetKind()])
	if err != nil {
		return nil, err
	}
	out := &pantherclawv1.ListEnvelopesResponse{NextPageToken: p.Next}
	for _, e := range p.Items {
		ep, err := EnvelopeProto(e)
		if err != nil {
			return nil, err
		}
		out.Envelopes = append(out.Envelopes, ep)
	}
	return out, nil
}
