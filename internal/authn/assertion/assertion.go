// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package assertion verifies RFC 7523 client assertions ("private_key_jwt"),
// signed by a service account's key or by a CLI's device key (SB-2,
// ADR-0016), and handles the public keys they are verified with.
//
// Algorithms are pinned per key (HR-095): a key is registered with exactly
// one algorithm (EdDSA or ES256) and an assertion is parsed with an
// allowlist containing only that algorithm, so "none", HMAC with the public
// key as secret, or a different asymmetric algorithm never verify. Keys are
// never taken from the assertion (jwk, jku, x5u, x5c headers are rejected).
//
// The caller must record the returned jti in the replay store only after
// Verify succeeded (HR-090 ordering), and reject a jti seen before.
package assertion

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"encoding/base64"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
)

// Limits (SB-2).
const (
	// MaxLifetime bounds exp - now and exp - iat.
	MaxLifetime = 5 * time.Minute
	// Leeway tolerates client clock skew for iat and nbf.
	Leeway = 30 * time.Second
	// MaxBytes bounds an assertion before parsing.
	MaxBytes = 8 << 10
	// MaxJTI bounds the jti claim (the replay store column).
	MaxJTI = 128
)

// Alg is a permitted assertion algorithm.
type Alg string

// Permitted algorithms.
const (
	EdDSA Alg = "EdDSA"
	ES256 Alg = "ES256"
)

// ErrInvalid is returned for every rejected assertion or key; the wrapped
// detail is for logs only.
var ErrInvalid = errors.New("assertion: invalid client assertion")

// PublicKey is a registered public key with its pinned algorithm.
type PublicKey struct {
	Alg Alg
	key crypto.PublicKey
	// Thumbprint is the RFC 7638 SHA-256 thumbprint (base64url), used as
	// the key id.
	Thumbprint string
	// Canonical is the minimal JWK (kty, crv, x, y) that is stored.
	Canonical []byte
}

// ParsePublicJWK parses a public JWK for algorithm alg. The JWK must be a
// public Ed25519 (EdDSA) or P-256 (ES256) key; private members, a different
// "alg", a "use" other than "sig", and certificate members are rejected.
func ParsePublicJWK(alg Alg, raw []byte) (PublicKey, error) {
	if len(raw) == 0 || len(raw) > 4096 {
		return PublicKey{}, fmt.Errorf("%w: key size", ErrInvalid)
	}
	var members map[string]jsontext.Value
	if err := json.Unmarshal(raw, &members); err != nil {
		return PublicKey{}, fmt.Errorf("%w: key json: %w", ErrInvalid, err)
	}
	for m := range members {
		switch m {
		case "kty", "crv", "x", "y", "kid", "alg", "use", "key_ops":
		default:
			return PublicKey{}, fmt.Errorf("%w: key member %q not allowed", ErrInvalid, m)
		}
	}
	var jwk jose.JSONWebKey
	if err := jwk.UnmarshalJSON(raw); err != nil {
		return PublicKey{}, fmt.Errorf("%w: key: %w", ErrInvalid, err)
	}
	if !jwk.IsPublic() || !jwk.Valid() || (jwk.Algorithm != "" && jwk.Algorithm != string(alg)) ||
		(jwk.Use != "" && jwk.Use != "sig") {
		return PublicKey{}, fmt.Errorf("%w: key must be a public signing key for %s", ErrInvalid, alg)
	}
	var canonical map[string]string
	switch alg {
	case EdDSA:
		k, ok := jwk.Key.(ed25519.PublicKey)
		if !ok || len(k) != ed25519.PublicKeySize {
			return PublicKey{}, fmt.Errorf("%w: EdDSA needs an Ed25519 key", ErrInvalid)
		}
		canonical = map[string]string{"kty": "OKP", "crv": "Ed25519", "x": b64(k)}
	case ES256:
		k, ok := jwk.Key.(*ecdsa.PublicKey)
		if !ok || k.Curve != elliptic.P256() {
			return PublicKey{}, fmt.Errorf("%w: ES256 needs a P-256 key", ErrInvalid)
		}
		b, err := k.Bytes() // uncompressed point; validates it is on the curve
		if err != nil || len(b) != 65 {
			return PublicKey{}, fmt.Errorf("%w: invalid P-256 point", ErrInvalid)
		}
		canonical = map[string]string{"kty": "EC", "crv": "P-256", "x": b64(b[1:33]), "y": b64(b[33:])}
	default:
		return PublicKey{}, fmt.Errorf("%w: algorithm %q not permitted", ErrInvalid, alg)
	}
	tp, err := (&jose.JSONWebKey{Key: jwk.Key}).Thumbprint(crypto.SHA256)
	if err != nil {
		return PublicKey{}, fmt.Errorf("%w: thumbprint: %w", ErrInvalid, err)
	}
	out, err := json.Marshal(canonical, json.Deterministic(true))
	if err != nil {
		return PublicKey{}, err
	}
	return PublicKey{Alg: alg, key: jwk.Key, Thumbprint: b64(tp), Canonical: out}, nil
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// Expect describes what the assertion must say.
type Expect struct {
	// ClientID must equal both iss and sub.
	ClientID string
	// Audiences lists acceptable aud values; aud must be a single string
	// equal to one of them (the issuer or the token endpoint URL).
	Audiences []string
	Now       time.Time
}

// Verified is an assertion that passed verification.
type Verified struct {
	JTI       string
	ExpiresAt time.Time
}

// header is the only protected header shape accepted.
type header struct {
	Alg string `json:"alg"`
	Kid string `json:"kid"`
	Typ string `json:"typ,omitzero"`
}

// KeyID returns the kid header of an assertion without verifying it, so the
// caller can look up the registered key. Never trust anything else from an
// unverified assertion.
func KeyID(compact string) (string, error) {
	h, err := parseHeader(compact)
	if err != nil {
		return "", err
	}
	return h.Kid, nil
}

func parseHeader(compact string) (header, error) {
	var h header
	if len(compact) > MaxBytes || strings.Count(compact, ".") != 2 || strings.ContainsAny(compact, " \t\r\n") {
		return h, fmt.Errorf("%w: malformed", ErrInvalid)
	}
	raw, err := base64.RawURLEncoding.Strict().DecodeString(compact[:strings.IndexByte(compact, '.')])
	if err != nil {
		return h, fmt.Errorf("%w: header encoding", ErrInvalid)
	}
	if err := json.Unmarshal(raw, &h, json.RejectUnknownMembers(true)); err != nil {
		return h, fmt.Errorf("%w: header: %w", ErrInvalid, err)
	}
	if h.Kid == "" || len(h.Kid) > 128 {
		return h, fmt.Errorf("%w: kid required", ErrInvalid)
	}
	if h.Typ != "" && h.Typ != "JWT" && h.Typ != "client-authentication+jwt" {
		return h, fmt.Errorf("%w: typ %q", ErrInvalid, h.Typ)
	}
	return h, nil
}

// claims of an assertion. Unknown claims are ignored (client libraries add
// their own); the checked ones must have exactly these types.
type claims struct {
	Issuer    string         `json:"iss"`
	Subject   string         `json:"sub"`
	Audience  jsontext.Value `json:"aud"`
	JTI       string         `json:"jti"`
	Expiry    *float64       `json:"exp"`
	IssuedAt  *float64       `json:"iat"`
	NotBefore *float64       `json:"nbf"`
}

// Verify verifies compact against key and checks its claims.
func Verify(compact string, key PublicKey, e Expect) (Verified, error) {
	bad := func(format string, a ...any) (Verified, error) {
		return Verified{}, fmt.Errorf("%w: "+format, append([]any{ErrInvalid}, a...)...)
	}
	h, err := parseHeader(compact)
	if err != nil {
		return Verified{}, err
	}
	if h.Alg != string(key.Alg) || h.Kid != key.Thumbprint {
		return bad("alg %q / kid do not match the registered key", h.Alg)
	}
	obj, err := jose.ParseSignedCompact(compact, []jose.SignatureAlgorithm{jose.SignatureAlgorithm(key.Alg)})
	if err != nil {
		return bad("%w", err)
	}
	if len(obj.Signatures) != 1 {
		return bad("expected one signature")
	}
	payload, err := obj.Verify(key.key)
	if err != nil {
		return bad("%w", err)
	}
	var c claims
	if err := json.Unmarshal(payload, &c); err != nil {
		return bad("claims: %w", err)
	}
	var aud string
	if err := json.Unmarshal(c.Audience, &aud); err != nil {
		return bad("aud must be a single string")
	}
	exp, okExp := unix(c.Expiry)
	iat, okIat := unix(c.IssuedAt)
	nbf, okNbf := unix(c.NotBefore)
	switch {
	case e.ClientID == "" || c.Issuer != e.ClientID || c.Subject != e.ClientID:
		return bad("iss and sub must equal the client id")
	case !contains(e.Audiences, aud):
		return bad("audience")
	case c.JTI == "" || len(c.JTI) > MaxJTI:
		return bad("jti")
	case !okExp || (c.IssuedAt != nil && !okIat) || (c.NotBefore != nil && !okNbf):
		return bad("exp required; numeric dates must be finite")
	case !e.Now.Before(exp):
		return bad("expired")
	case exp.Sub(e.Now) > MaxLifetime:
		return bad("exp too far ahead")
	case okIat && (iat.After(e.Now.Add(Leeway)) || exp.Sub(iat) > MaxLifetime):
		return bad("iat")
	case okNbf && nbf.After(e.Now.Add(Leeway)):
		return bad("not yet valid")
	}
	return Verified{JTI: c.JTI, ExpiresAt: exp}, nil
}

func unix(f *float64) (time.Time, bool) {
	if f == nil || math.IsNaN(*f) || math.IsInf(*f, 0) || *f < 0 || *f > 1<<40 {
		return time.Time{}, false
	}
	return time.Unix(int64(*f), 0), true
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x != "" && x == s {
			return true
		}
	}
	return false
}
