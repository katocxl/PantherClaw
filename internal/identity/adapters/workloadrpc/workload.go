// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package workloadrpc serves WorkloadService, the API agent workloads call
// (PAP-1 §3–§4, G0 M3). It is authenticated by PAP/1, not by user or
// service credentials: RawBody hashes every request body before anything
// parses it (HR-091), and each handler verifies the PAP-Proof header (and
// the workload token when one is sent) over exactly that request, then
// consumes the proof, before doing anything else (HR-090). A failure is
// Unauthenticated with a PAP-Error code; responses carry a fresh PAP-Nonce
// for the org whenever the org is known.
package workloadrpc

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"connectrpc.com/connect/v2"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/katocxl/pantherclaw/internal/authn/credential"
	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	"github.com/katocxl/pantherclaw/internal/identity/app"
	"github.com/katocxl/pantherclaw/internal/identity/issuers"
	"github.com/katocxl/pantherclaw/internal/identity/pap"
	"github.com/katocxl/pantherclaw/internal/platform/clock"
	"github.com/katocxl/pantherclaw/internal/platform/httpx"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// Prefix is the URL path prefix of WorkloadService procedures.
const Prefix = "/" + pantherclawv1connect.WorkloadServiceName + "/"

// MaxBody bounds a workload request body; WorkloadService messages are
// small (the largest field is a 16 KiB attestation token).
const MaxBody = 64 << 10

type rawKey struct{}

type raw struct {
	sum      [32]byte
	clientIP string
}

// RawBody hashes the raw body of every WorkloadService request before any
// parsing and records the client address (HR-091, HR-092). Other requests
// pass through untouched.
func RawBody(next http.Handler, clientIP httpx.ClientIPFunc) http.Handler {
	if clientIP == nil {
		clientIP = httpx.ClientIP
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, Prefix) {
			next.ServeHTTP(w, r)
			return
		}
		body, err := io.ReadAll(io.LimitReader(r.Body, MaxBody+1))
		if err != nil || len(body) > MaxBody {
			http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
			return
		}
		ctx := context.WithValue(r.Context(), rawKey{}, raw{sum: sha256.Sum256(body), clientIP: clientIP(r)})
		r = r.WithContext(ctx)
		r.Body = io.NopCloser(bytes.NewReader(body))
		next.ServeHTTP(w, r)
	})
}

// Workload serves WorkloadService.
type Workload struct {
	pantherclawv1connect.UnimplementedWorkloadServiceHandler
	svc       *app.Service
	publicURL string
	clk       clock.Clock
}

// NewWorkload returns the WorkloadService handler. publicURL is the
// server's configured public URL: proofs are checked against it, never
// against the Host header.
func NewWorkload(svc *app.Service, publicURL string, clk clock.Clock) *Workload {
	return &Workload{svc: svc, publicURL: strings.TrimSuffix(publicURL, "/"), clk: clk}
}

// papError turns a PAP failure into Unauthenticated with its PAP-Error code
// and, when the org is known, a fresh nonce.
func (s *Workload) papError(ctx context.Context, info *connect.CallInfo, org ids.OrgID, err error) error {
	var pe *pap.Error
	if !errors.As(err, &pe) {
		return err
	}
	info.ResponseHeader().Set("PAP-Error", string(pe.Code))
	s.setNonce(ctx, info, org)
	return connect.NewError(connect.CodeUnauthenticated, "PAP/1: "+string(pe.Code))
}

func (s *Workload) setNonce(ctx context.Context, info *connect.CallInfo, org ids.OrgID) {
	if org.IsZero() {
		return
	}
	if n, err := s.svc.Nonce(ctx, org); err == nil {
		info.ResponseHeader().Set("PAP-Nonce", n)
	}
}

// verify checks the request's PAP/1 credentials (PAP-1 §4 steps 1–5).
func (s *Workload) verify(ctx context.Context, info *connect.CallInfo) (pap.Checked, raw, error) {
	rb, ok := ctx.Value(rawKey{}).(raw)
	if !ok {
		return pap.Checked{}, raw{}, pap.Err(pap.CodeInvalidProof) // RawBody not mounted: fail closed
	}
	token, _ := strings.CutPrefix(info.RequestHeader().Get("Authorization"), "PAP ")
	verifier, err := s.svc.TokenVerifier()
	if err != nil {
		return pap.Checked{}, rb, err
	}
	c, err := pap.VerifyRequest(verifier, s.svc.Issuer(), pap.Request{
		Method: http.MethodPost, URL: s.publicURL + info.Spec.Procedure, BodySHA256: rb.sum, Token: token,
	}, info.RequestHeader().Get("PAP-Proof"), s.clk.Now())
	return c, rb, err
}

func callInfo(ctx context.Context) (*connect.CallInfo, error) {
	info, ok := connect.CallInfoForServerContext(ctx)
	if !ok {
		return nil, connect.NewError(connect.CodeInternal, "no call info")
	}
	return info, nil
}

// Enroll implements WorkloadServiceHandler.
func (s *Workload) Enroll(ctx context.Context, req *pantherclawv1.EnrollRequest) (*pantherclawv1.EnrollResponse, error) {
	info, err := callInfo(ctx)
	if err != nil {
		return nil, err
	}
	att := attestation(req.GetAttestation())
	var org ids.OrgID
	if tok, err := credential.Parse(credential.EnrollmentToken, req.GetEnrollmentToken()); err == nil {
		org = tok.Org()
	} else if req.GetEnrollmentToken() == "" && att != nil {
		org = app.AttestationOrg(att.Token)
	}
	c, rb, err := s.verify(ctx, info)
	if err != nil {
		return nil, s.papError(ctx, info, org, err)
	}
	e, err := s.svc.Enroll(ctx, app.EnrollInput{
		Proof: c, EnrollmentToken: req.GetEnrollmentToken(), Attestation: att, PublicJWK: []byte(req.GetPublicJwk()),
		DeclaredRelease: req.GetDeclaredReleaseDigest(), ClientAddress: rb.clientIP,
	})
	if err != nil {
		return nil, s.papError(ctx, info, org, err)
	}
	s.setNonce(ctx, info, org)
	resp := &pantherclawv1.EnrollResponse{
		InstanceId: e.Instance.Instance.String(), Identifier: e.Instance.String(),
		State: pantherclawv1.InstanceState_INSTANCE_STATE_PENDING_ADMISSION, Fingerprint: e.Fingerprint,
	}
	if e.State == "ADMITTED" {
		resp.State, resp.AttestationLevel = pantherclawv1.InstanceState_INSTANCE_STATE_ADMITTED, int32(e.Level) //nolint:gosec // G115: 1 or 2
	}
	return resp, nil
}

// IssueToken implements WorkloadServiceHandler.
func (s *Workload) IssueToken(ctx context.Context, req *pantherclawv1.IssueTokenRequest) (*pantherclawv1.IssueTokenResponse, error) {
	info, err := callInfo(ctx)
	if err != nil {
		return nil, err
	}
	var org ids.OrgID
	if id, err := pap.ParseInstance(req.GetIdentifier()); err == nil {
		org = id.Org
	}
	c, rb, err := s.verify(ctx, info)
	if err != nil {
		return nil, s.papError(ctx, info, org, err)
	}
	iss, err := s.svc.IssueToken(ctx, app.TokenInput{
		Proof: c, Identifier: req.GetIdentifier(), Attestation: attestation(req.GetAttestation()), DeclaredRelease: req.GetDeclaredReleaseDigest(), ClientAddress: rb.clientIP,
	})
	if err != nil {
		return nil, s.papError(ctx, info, org, err)
	}
	s.setNonce(ctx, info, org)
	return &pantherclawv1.IssueTokenResponse{
		WorkloadToken: iss.Token, ExpireTime: ts(iss.ExpiresAt), AttestationLevel: int32(iss.Level), //nolint:gosec // G115: 1 or 2
	}, nil
}

// attestation maps the request's attestation to its preset.
func attestation(a *pantherclawv1.Attestation) *app.Attestation {
	if a == nil {
		return nil
	}
	kind := issuers.KindGitHub
	if a.GetKind() == pantherclawv1.AttestationKind_ATTESTATION_KIND_KUBERNETES {
		kind = issuers.KindKubernetes
	}
	return &app.Attestation{Kind: kind, Token: a.GetToken()}
}

func ts(t time.Time) *timestamppb.Timestamp {
	if t.IsZero() {
		return nil
	}
	return timestamppb.New(t)
}
