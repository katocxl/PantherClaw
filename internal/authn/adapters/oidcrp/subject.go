// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package oidcrp

import (
	"context"
	"encoding/base64"
	"encoding/json/v2"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"

	authnapp "github.com/katocxl/pantherclaw/internal/authn/app"
)

// Subject token limits (HR-145).
const (
	SubjectMaxAge   = 5 * time.Minute
	SubjectSkew     = 60 * time.Second
	maxSubjectToken = 16 << 10
)

// ErrSubjectToken is returned for every subject token that is not
// accepted; the detail is for logs only.
var ErrSubjectToken = errors.New("oidcrp: subject token rejected")

func subjectErr(format string, a ...any) error {
	return fmt.Errorf("%w: %s", ErrSubjectToken, fmt.Sprintf(format, a...))
}

// segment decodes one part of a compact JWS as a JSON object. Anything
// else (an opaque token) is refused.
func segment(raw string, i int, v any) error {
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return subjectErr("not a signed JWT")
	}
	b, err := base64.RawURLEncoding.DecodeString(parts[i])
	if err != nil {
		return subjectErr("encoding")
	}
	if err := json.Unmarshal(b, v); err != nil {
		return subjectErr("malformed JWT")
	}
	return nil
}

// VerifySubject verifies an RFC 8693 subject token issued by this provider
// (HR-145, PAP-1 §5): a JWT signed with RS256, ES256 or EdDSA by the
// provider's published keys, whose aud contains the configured
// subject_token_audience, unexpired, issued at most SubjectMaxAge before
// now (SubjectSkew either way), with a subject. An access token must carry
// the JWS typ at+jwt (RFC 9068) and an ID token must not, so one type
// cannot pass for the other. An unreachable provider refuses the token.
func (p *Provider) VerifySubject(ctx context.Context, raw string, accessToken bool, now time.Time) (authnapp.SubjectClaims, error) {
	if p.cfg.SubjectTokenAudience == "" {
		return authnapp.SubjectClaims{}, subjectErr("provider %s does not accept subject tokens", p.cfg.Name)
	}
	if len(raw) > maxSubjectToken {
		return authnapp.SubjectClaims{}, subjectErr("too large")
	}
	var h struct {
		Typ string `json:"typ"`
	}
	if err := segment(raw, 0, &h); err != nil {
		return authnapp.SubjectClaims{}, err
	}
	typ := strings.ToLower(h.Typ)
	if isAT := typ == "at+jwt" || typ == "application/at+jwt"; isAT != accessToken {
		return authnapp.SubjectClaims{}, subjectErr("typ %q does not match the declared token type", h.Typ)
	}
	d, err := p.load(ctx)
	if err != nil {
		return authnapp.SubjectClaims{}, err
	}
	tok, err := d.subject.Verify(oidc.ClientContext(ctx, p.client), raw)
	if err != nil {
		return authnapp.SubjectClaims{}, subjectErr("%v", err)
	}
	var c struct {
		JTI string `json:"jti"`
	}
	if err := tok.Claims(&c); err != nil {
		return authnapp.SubjectClaims{}, subjectErr("claims: %v", err)
	}
	switch age := now.Sub(tok.IssuedAt); {
	case tok.IssuedAt.IsZero():
		return authnapp.SubjectClaims{}, subjectErr("no iat")
	case age > SubjectMaxAge+SubjectSkew || age < -SubjectSkew:
		return authnapp.SubjectClaims{}, subjectErr("issued %s ago", age.Round(time.Second))
	case !tok.Expiry.After(now):
		return authnapp.SubjectClaims{}, subjectErr("expired")
	case tok.Subject == "" || len(tok.Subject) > 255 || len(c.JTI) > 1024:
		return authnapp.SubjectClaims{}, subjectErr("sub or jti")
	}
	return authnapp.SubjectClaims{Issuer: tok.Issuer, Subject: tok.Subject, JTI: c.JTI, ExpiresAt: tok.Expiry}, nil
}

// Subjects are the providers configured with a subject_token_audience.
type Subjects []*Provider

// VerifySubject picks the provider the token names in its iss (read before
// verification only to choose), which then verifies everything.
func (s Subjects) VerifySubject(ctx context.Context, raw string, accessToken bool, now time.Time) (authnapp.SubjectClaims, error) {
	var c struct {
		Iss string `json:"iss"`
	}
	if err := segment(raw, 1, &c); err != nil {
		return authnapp.SubjectClaims{}, err
	}
	for _, p := range s {
		if p.cfg.SubjectTokenAudience != "" && p.cfg.Issuer == c.Iss {
			return p.VerifySubject(ctx, raw, accessToken, now)
		}
	}
	return authnapp.SubjectClaims{}, subjectErr("no provider accepts subject tokens from this issuer")
}
