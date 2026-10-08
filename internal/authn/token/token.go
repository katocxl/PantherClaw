// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package token issues and verifies PantherClaw access tokens (ADR-0016):
// compact JWS, EdDSA only, typ "at+jwt" (RFC 9068), signed by the dedicated
// access_tokens key and valid for at most 15 minutes. Verification here is
// cryptographic and structural only; the caller must still check that the
// principal, its session or key and its org are active (per request).
package token

import (
	"encoding/json/v2"
	"errors"
	"fmt"
	"time"

	"github.com/katocxl/pantherclaw/internal/platform/crypto/jws"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/keys"
	"github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

const (
	// Type is the typ header of access tokens.
	Type = "at+jwt"
	// TTL is the lifetime of every access token (SB-2).
	TTL = 15 * time.Minute
	// Leeway tolerates clock differences between server replicas for
	// iat/nbf only; expiry is never extended.
	Leeway = 30 * time.Second
)

// ErrInvalid is returned for every rejected token; the wrapped detail is for
// logs only.
var ErrInvalid = errors.New("token: invalid access token")

// KeySource provides the signing and verification keys (*keys.Registry).
type KeySource interface {
	Signer(keys.Purpose) (*jws.Signer, error)
	Verifier(keys.Purpose, string) (*jws.Verifier, error)
}

// Grant describes the principal a token is issued to.
type Grant struct {
	Org       ids.OrgID
	Principal domain.PrincipalRef
	// Session is the CLI session (users) or the service-account key the
	// client assertion was signed with; revoking it invalidates the token.
	Session  ids.UUID
	ClientID string
}

// Verified is a token that passed verification.
type Verified struct {
	Grant
	ID        string
	ExpiresAt time.Time
}

// claims is the token payload. Unknown members are rejected on decode.
type claims struct {
	Issuer    string `json:"iss"`
	Subject   string `json:"sub"`
	Audience  string `json:"aud"`
	Org       string `json:"pc_org"`
	Kind      string `json:"pc_ptyp"`
	Session   string `json:"sid"`
	ClientID  string `json:"client_id"`
	ID        string `json:"jti"`
	IssuedAt  int64  `json:"iat"`
	NotBefore int64  `json:"nbf"`
	Expiry    int64  `json:"exp"`
}

// Service issues and verifies access tokens for one issuer and audience.
type Service struct {
	keys     KeySource
	issuer   string
	audience string
}

// New returns a Service. issuer is the server's public URL; audience names
// the API.
func New(ks KeySource, issuer, audience string) (*Service, error) {
	if ks == nil || issuer == "" || audience == "" {
		return nil, errors.New("token: key source, issuer and audience are required")
	}
	return &Service{keys: ks, issuer: issuer, audience: audience}, nil
}

// Issue signs a token for g, valid from now for TTL.
func (s *Service) Issue(g Grant, now time.Time) (string, time.Time, error) {
	if g.Org.IsZero() || g.Principal.ID.IsZero() || g.Session.IsZero() || g.ClientID == "" ||
		(g.Principal.Kind != domain.KindUser && g.Principal.Kind != domain.KindServiceAccount) {
		return "", time.Time{}, errors.New("token: incomplete grant")
	}
	now = now.Truncate(time.Second)
	exp := now.Add(TTL)
	payload, err := json.Marshal(claims{
		Issuer: s.issuer, Subject: g.Principal.ID.String(), Audience: s.audience,
		Org: g.Org.String(), Kind: string(g.Principal.Kind), Session: g.Session.String(), ClientID: g.ClientID,
		ID: ids.NewV7().String(), IssuedAt: now.Unix(), NotBefore: now.Unix(), Expiry: exp.Unix(),
	})
	if err != nil {
		return "", time.Time{}, err
	}
	signer, err := s.keys.Signer(keys.PurposeAccessTokens)
	if err != nil {
		return "", time.Time{}, err
	}
	compact, err := signer.Sign(Type, payload)
	if err != nil {
		return "", time.Time{}, err
	}
	return compact, exp, nil
}

// Verify checks signature, type, issuer, audience, validity window and claim
// shapes. It does not consult the database.
func (s *Service) Verify(compact string, now time.Time) (Verified, error) {
	v, err := s.keys.Verifier(keys.PurposeAccessTokens, Type)
	if err != nil {
		return Verified{}, fmt.Errorf("%w: %w", ErrInvalid, err)
	}
	payload, _, err := v.Verify(compact)
	if err != nil {
		return Verified{}, fmt.Errorf("%w: %w", ErrInvalid, err)
	}
	var c claims
	if err := json.Unmarshal(payload, &c, json.RejectUnknownMembers(true)); err != nil {
		return Verified{}, fmt.Errorf("%w: claims: %w", ErrInvalid, err)
	}
	return s.check(c, now)
}

func (s *Service) check(c claims, now time.Time) (Verified, error) {
	bad := func(what string) (Verified, error) { return Verified{}, fmt.Errorf("%w: %s", ErrInvalid, what) }
	iat, nbf, exp := time.Unix(c.IssuedAt, 0), time.Unix(c.NotBefore, 0), time.Unix(c.Expiry, 0)
	switch {
	case c.Issuer != s.issuer:
		return bad("issuer")
	case c.Audience != s.audience:
		return bad("audience")
	case !now.Before(exp):
		return bad("expired")
	case nbf.After(now.Add(Leeway)) || iat.After(now.Add(Leeway)):
		return bad("not yet valid")
	case !exp.After(iat) || exp.Sub(iat) > TTL || nbf.Before(iat):
		return bad("lifetime")
	case c.ID == "" || len(c.ID) > 64 || c.ClientID == "" || len(c.ClientID) > 128:
		return bad("jti or client_id")
	}
	kind := domain.PrincipalKind(c.Kind)
	if kind != domain.KindUser && kind != domain.KindServiceAccount {
		return bad("principal type")
	}
	org, err := ids.Parse[ids.Org](c.Org)
	if err != nil {
		return bad("org")
	}
	sub, err := parseV7(c.Subject)
	if err != nil {
		return bad("subject")
	}
	sid, err := parseV7(c.Session)
	if err != nil {
		return bad("session")
	}
	return Verified{
		Grant: Grant{Org: org, Principal: domain.PrincipalRef{Kind: kind, ID: sub}, Session: sid, ClientID: c.ClientID},
		ID:    c.ID, ExpiresAt: exp,
	}, nil
}

type anyID struct{}

func (anyID) KindName() string { return "id" }

func parseV7(s string) (ids.UUID, error) {
	id, err := ids.Parse[anyID](s)
	return id.UUID(), err
}

// Audience is the aud of every PantherClaw access token: the control-plane
// API.
const Audience = "pantherclaw-api"
