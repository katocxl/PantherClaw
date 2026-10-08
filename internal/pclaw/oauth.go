// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pclaw

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"

	"github.com/katocxl/pantherclaw/internal/authn/assertion"
)

// Endpoint paths and constants shared with the server (authn/app).
const (
	clientID      = "pclaw"
	assertionType = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
	tokenPath     = "/oauth2/token" //nolint:gosec // G101: an endpoint path, not a credential
	devicePath    = "/oauth2/device_authorization"
	revokePath    = "/oauth2/revoke"
)

// checkServer accepts https URLs, and http only on a loopback host, with no
// path, query or credentials (the same rule as the server's public_url).
func checkServer(raw string) (string, error) {
	u, err := url.Parse(strings.TrimRight(raw, "/"))
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Path != "" {
		return "", fmt.Errorf("--server must be a base URL like https://pantherclaw.example.com")
	}
	host := u.Hostname()
	if u.Scheme != "https" && (u.Scheme != "http" || (host != "localhost" && host != "127.0.0.1" && host != "::1")) {
		return "", fmt.Errorf("--server must use https (http only for localhost)")
	}
	return u.Scheme + "://" + u.Host, nil
}

type oauthError struct {
	Code        string `json:"error"`
	Description string `json:"error_description"`
}

func (e *oauthError) Error() string {
	if e.Description != "" {
		return e.Code + ": " + e.Description
	}
	return e.Code
}

type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
}

type deviceAuthorization struct {
	DeviceCode              string `json:"device_code"`
	UserCode                string `json:"user_code"`
	VerificationURI         string `json:"verification_uri"`
	VerificationURIComplete string `json:"verification_uri_complete"`
	ExpiresIn               int    `json:"expires_in"`
	Interval                int    `json:"interval"`
}

type oauthClient struct {
	server string
	http   *http.Client
}

// post sends a form and decodes a JSON success into out, or returns an
// *oauthError.
func (o oauthClient) post(ctx context.Context, path string, form url.Values, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, o.server+path, strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	res, err := o.http.Do(req)
	if err != nil {
		return fmt.Errorf("pclaw: %s: %w", o.server, err)
	}
	defer func() { _ = res.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(res.Body, 64<<10))
	if err != nil {
		return err
	}
	if res.StatusCode != http.StatusOK {
		var oe oauthError
		if json.Unmarshal(body, &oe) == nil && oe.Code != "" {
			return &oe
		}
		return fmt.Errorf("pclaw: %s%s: HTTP %d", o.server, path, res.StatusCode)
	}
	if out == nil {
		return nil
	}
	return json.Unmarshal(body, out)
}

// deviceAssertion signs an RFC 7523 client assertion with the device key.
func deviceAssertion(priv ed25519.PrivateKey, aud string) (string, error) {
	pk, err := publicJWK(priv)
	if err != nil {
		return "", err
	}
	now := time.Now()
	claims, err := json.Marshal(map[string]any{
		"iss": clientID, "sub": clientID, "aud": aud, "jti": rand.Text(), "iat": now.Unix(), "exp": now.Add(time.Minute).Unix(),
	})
	if err != nil {
		return "", err
	}
	s, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.EdDSA, Key: priv},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", pk.Thumbprint))
	if err != nil {
		return "", err
	}
	obj, err := s.Sign(claims)
	if err != nil {
		return "", err
	}
	return obj.CompactSerialize()
}

func publicJWK(priv ed25519.PrivateKey) (assertion.PublicKey, error) {
	raw, err := jose.JSONWebKey{Key: priv.Public()}.MarshalJSON()
	if err != nil {
		return assertion.PublicKey{}, err
	}
	return assertion.ParsePublicJWK(assertion.EdDSA, raw)
}

func (o oauthClient) withAssertion(form url.Values, priv ed25519.PrivateKey) (url.Values, error) {
	a, err := deviceAssertion(priv, o.server+tokenPath)
	if err != nil {
		return nil, err
	}
	form.Set("client_id", clientID)
	form.Set("client_assertion_type", assertionType)
	form.Set("client_assertion", a)
	return form, nil
}

func (o oauthClient) refresh(ctx context.Context, rt string, priv ed25519.PrivateKey) (tokenResponse, error) {
	form, err := o.withAssertion(url.Values{"grant_type": {"refresh_token"}, "refresh_token": {rt}}, priv)
	if err != nil {
		return tokenResponse{}, err
	}
	var tr tokenResponse
	err = o.post(ctx, tokenPath, form, &tr)
	return tr, err
}

func (o oauthClient) revoke(ctx context.Context, rt string) error {
	return o.post(ctx, revokePath, url.Values{"token": {rt}, "token_type_hint": {"refresh_token"}}, nil)
}

// errExpired reports that the person did not finish in time.
var errExpired = errors.New("the code expired before the sign-in finished; run pclaw login again")
