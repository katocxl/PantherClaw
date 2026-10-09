// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package workloadclient is the workload side of PAP/1 (PAP-1 §4): an HTTP
// transport that signs a proof over every request's exact method, URL and
// body, sends the workload token when it has one, and keeps the server's
// latest nonce, retrying once when the server asks for a fresh one. It is
// used by pclaw, the simulator and tests; the public SDKs (M8) follow the
// same protocol.
package workloadclient

import (
	"bytes"
	"crypto/ed25519"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/katocxl/pantherclaw/internal/identity/pap"
	"github.com/katocxl/pantherclaw/internal/platform/httpx"
)

// Transport signs PAP/1 proofs for every request.
type Transport struct {
	// Key is the workload's private key; it never leaves the workload.
	Key ed25519.PrivateKey
	// Base sends the signed request; when nil, the hardened control-plane
	// transport (no redirects, no proxy variables, HR-070, HR-072).
	Base http.RoundTripper
	// Token returns the current workload token, or "" for key-only proofs
	// (enrollment, token issuance).
	Token func() string
	// Now is the clock (time.Now when nil).
	Now func() time.Time

	mu    sync.Mutex
	nonce string
	once  sync.Once
	def   http.RoundTripper
}

// Nonce returns the last nonce the server sent.
func (t *Transport) Nonce() string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.nonce
}

// RoundTrip implements http.RoundTripper.
func (t *Transport) RoundTrip(r *http.Request) (*http.Response, error) {
	var body []byte
	if r.Body != nil {
		var err error
		if body, err = io.ReadAll(r.Body); err != nil {
			return nil, err
		}
		_ = r.Body.Close()
	}
	resp, err := t.send(r, body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode == http.StatusUnauthorized && resp.Header.Get("PAP-Error") == string(pap.CodeUseNonce) &&
		resp.Header.Get("PAP-Nonce") != "" {
		_ = resp.Body.Close()
		return t.send(r, body)
	}
	return resp, nil
}

func (t *Transport) send(r *http.Request, body []byte) (*http.Response, error) {
	now := time.Now
	if t.Now != nil {
		now = t.Now
	}
	var token string
	if t.Token != nil {
		token = t.Token()
	}
	u := *r.URL
	u.RawQuery, u.Fragment = "", ""
	proof, err := pap.NewProof(t.Key, pap.ProofParams{
		Method: r.Method, URL: u.String(), Body: body, Token: token, Nonce: t.Nonce(), Now: now(),
	})
	if err != nil {
		return nil, err
	}
	req := r.Clone(r.Context())
	req.Body = io.NopCloser(bytes.NewReader(body))
	req.ContentLength = int64(len(body))
	req.Header.Set("PAP-Proof", proof)
	if token != "" {
		req.Header.Set("Authorization", "PAP "+token)
	} else {
		req.Header.Del("Authorization")
	}
	base := t.Base
	if base == nil {
		t.once.Do(func() { t.def = httpx.NewControlClient(httpx.ControlConfig{}).Transport })
		base = t.def
	}
	resp, err := base.RoundTrip(req)
	if err != nil {
		return nil, err
	}
	if n := resp.Header.Get("PAP-Nonce"); n != "" {
		t.mu.Lock()
		t.nonce = n
		t.mu.Unlock()
	}
	return resp, nil
}
