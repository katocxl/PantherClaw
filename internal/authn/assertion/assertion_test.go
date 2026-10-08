// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package assertion_test

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json/v2"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"

	"github.com/katocxl/pantherclaw/internal/authn/assertion"
)

const (
	clientID = "pcsa_0192aaaabbbb7ccc8ddd000000000001_0192aaaabbbb7ccc8ddd000000000002"
	tokenURL = "https://pc.example.test/oauth2/token"
	issuer   = "https://pc.example.test"
)

var now = time.Date(2026, 10, 8, 12, 0, 0, 0, time.UTC)

type testKey struct {
	alg  assertion.Alg
	priv any
	pub  assertion.PublicKey
}

func newKey(t *testing.T, alg assertion.Alg) testKey {
	t.Helper()
	var priv, pub any
	switch alg {
	case assertion.EdDSA:
		p, s, _ := ed25519.GenerateKey(rand.Reader)
		priv, pub = s, p
	case assertion.ES256:
		s, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		priv, pub = s, &s.PublicKey
	}
	raw, err := jose.JSONWebKey{Key: pub}.MarshalJSON()
	if err != nil {
		t.Fatal(err)
	}
	pk, err := assertion.ParsePublicJWK(alg, raw)
	if err != nil {
		t.Fatal(err)
	}
	return testKey{alg: alg, priv: priv, pub: pk}
}

func (k testKey) sign(t *testing.T, header, claims map[string]any) string {
	t.Helper()
	opts := &jose.SignerOptions{ExtraHeaders: map[jose.HeaderKey]any{}}
	opts.WithHeader("kid", k.pub.Thumbprint)
	for h, v := range header {
		opts.WithHeader(jose.HeaderKey(h), v)
	}
	s, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.SignatureAlgorithm(k.alg), Key: k.priv}, opts)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(claims)
	obj, err := s.Sign(b)
	if err != nil {
		t.Fatal(err)
	}
	out, err := obj.CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func claims() map[string]any {
	return map[string]any{
		"iss": clientID, "sub": clientID, "aud": tokenURL, "jti": "j-1",
		"iat": now.Unix(), "exp": now.Add(2 * time.Minute).Unix(),
	}
}

func expect() assertion.Expect {
	return assertion.Expect{ClientID: clientID, Audiences: []string{issuer, tokenURL}, Now: now}
}

func TestVerifyBothAlgorithms(t *testing.T) {
	for _, alg := range []assertion.Alg{assertion.EdDSA, assertion.ES256} {
		k := newKey(t, alg)
		v, err := assertion.Verify(k.sign(t, nil, claims()), k.pub, expect())
		if err != nil {
			t.Fatalf("%s: %v", alg, err)
		}
		if v.JTI != "j-1" || !v.ExpiresAt.Equal(now.Add(2*time.Minute)) {
			t.Fatalf("%s: %+v", alg, v)
		}
		c := claims()
		c["aud"] = issuer
		if _, err := assertion.Verify(k.sign(t, map[string]any{"typ": "JWT"}, c), k.pub, expect()); err != nil {
			t.Fatalf("%s with issuer audience and typ JWT: %v", alg, err)
		}
		if kid, err := assertion.KeyID(k.sign(t, nil, claims())); err != nil || kid != k.pub.Thumbprint {
			t.Fatalf("KeyID = %q, %v", kid, err)
		}
	}
}

func encode(m map[string]any) string {
	b, _ := json.Marshal(m)
	return base64.RawURLEncoding.EncodeToString(b)
}

// TestHR095_AssertionAlgorithmIsPinnedPerKey: none, HS256 keyed with the
// public key, the other asymmetric algorithm, an unknown kid, and keys
// embedded in the header are all rejected.
func TestHR095_AssertionAlgorithmIsPinnedPerKey(t *testing.T) {
	ed := newKey(t, assertion.EdDSA)
	es := newKey(t, assertion.ES256)
	payload := encode(claims())

	none := encode(map[string]any{"alg": "none", "kid": ed.pub.Thumbprint}) + "." + payload + "."
	hsHeader := encode(map[string]any{"alg": "HS256", "kid": ed.pub.Thumbprint})
	pubBytes, _ := base64.RawURLEncoding.DecodeString(strings.TrimSuffix(strings.Split(string(ed.pub.Canonical), `"x":"`)[1], `"}`))
	mac := hmac.New(sha256.New, pubBytes)
	mac.Write([]byte(hsHeader + "." + payload))
	hs := hsHeader + "." + payload + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	macCanon := hmac.New(sha256.New, ed.pub.Canonical)
	macCanon.Write([]byte(hsHeader + "." + payload))
	hsCanon := hsHeader + "." + payload + "." + base64.RawURLEncoding.EncodeToString(macCanon.Sum(nil))

	// An ES256 assertion presented against the EdDSA key (kid forged to match).
	otherAlg := es.sign(t, map[string]any{"kid": ed.pub.Thumbprint}, claims())
	jwkHeader := ed.sign(t, map[string]any{"jwk": map[string]any{"kty": "OKP"}}, claims())
	critHeader := ed.sign(t, map[string]any{"crit": []string{"exp"}}, claims())
	unknownKid := newKey(t, assertion.EdDSA).sign(t, nil, claims())

	for name, tok := range map[string]string{
		"alg none": none, "HS256 with public key": hs, "HS256 with canonical JWK": hsCanon,
		"ES256 against EdDSA key": otherAlg, "embedded jwk": jwkHeader, "crit header": critHeader,
		"signed by another key": unknownKid,
	} {
		if _, err := assertion.Verify(tok, ed.pub, expect()); !errors.Is(err, assertion.ErrInvalid) {
			t.Errorf("%s: err = %v", name, err)
		}
	}
}

// TestT032_AssertionClaimsAreChecked: audience confusion, subject or issuer
// substitution, missing jti/exp, and overlong or expired assertions.
func TestT032_AssertionClaimsAreChecked(t *testing.T) {
	k := newKey(t, assertion.EdDSA)
	cases := map[string]func(map[string]any){
		"ok":                func(map[string]any) {},
		"aud array":         func(c map[string]any) { c["aud"] = []string{tokenURL} },
		"aud other server":  func(c map[string]any) { c["aud"] = "https://evil.test/oauth2/token" },
		"aud missing":       func(c map[string]any) { delete(c, "aud") },
		"iss other client":  func(c map[string]any) { c["iss"] = clientID + "x" },
		"sub other client":  func(c map[string]any) { c["sub"] = "pcsa_other" },
		"no jti":            func(c map[string]any) { delete(c, "jti") },
		"long jti":          func(c map[string]any) { c["jti"] = strings.Repeat("j", 129) },
		"no exp":            func(c map[string]any) { delete(c, "exp") },
		"exp string":        func(c map[string]any) { c["exp"] = "soon" },
		"expired":           func(c map[string]any) { c["exp"] = now.Unix() },
		"exp too far":       func(c map[string]any) { c["exp"] = now.Add(10 * time.Minute).Unix() },
		"iat in future":     func(c map[string]any) { c["iat"] = now.Add(time.Minute).Unix() },
		"iat too old":       func(c map[string]any) { c["iat"] = now.Add(-10 * time.Minute).Unix() },
		"nbf in future":     func(c map[string]any) { c["nbf"] = now.Add(time.Minute).Unix() },
		"fractional dates":  func(c map[string]any) { c["exp"] = float64(now.Unix()) + 60.5 },
		"negative exp":      func(c map[string]any) { c["exp"] = -1 },
		"extra claims okay": func(c map[string]any) { c["scope"] = "x" },
	}
	for name, mutate := range cases {
		c := claims()
		mutate(c)
		_, err := assertion.Verify(k.sign(t, nil, c), k.pub, expect())
		wantOK := name == "ok" || name == "fractional dates" || name == "extra claims okay"
		if (err == nil) != wantOK {
			t.Errorf("%s: err = %v", name, err)
		}
	}
	if _, err := assertion.Verify(k.sign(t, map[string]any{"typ": "at+jwt"}, claims()), k.pub, expect()); err == nil {
		t.Error("access-token typ accepted as an assertion")
	}
	e := expect()
	e.ClientID = ""
	if _, err := assertion.Verify(k.sign(t, nil, claims()), k.pub, e); err == nil {
		t.Error("empty expected client id accepted")
	}
}

func TestParsePublicJWK(t *testing.T) {
	ed := newKey(t, assertion.EdDSA)
	// The canonical form re-parses to the same key and thumbprint.
	again, err := assertion.ParsePublicJWK(assertion.EdDSA, ed.pub.Canonical)
	if err != nil || again.Thumbprint != ed.pub.Thumbprint || string(again.Canonical) != string(ed.pub.Canonical) {
		t.Fatalf("canonical round trip: %v", err)
	}
	if len(ed.pub.Thumbprint) != 43 {
		t.Fatalf("thumbprint %q", ed.pub.Thumbprint)
	}
	_, edPriv, _ := ed25519.GenerateKey(rand.Reader)
	privJWK, _ := jose.JSONWebKey{Key: edPriv}.MarshalJSON()
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	rsaJWK, _ := jose.JSONWebKey{Key: &rsaKey.PublicKey}.MarshalJSON()
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	p384JWK, _ := jose.JSONWebKey{Key: &p384.PublicKey}.MarshalJSON()
	withAlg := strings.Replace(string(ed.pub.Canonical), "{", `{"alg":"ES256",`, 1)
	withUse := strings.Replace(string(ed.pub.Canonical), "{", `{"use":"enc",`, 1)
	withX5c := strings.Replace(string(ed.pub.Canonical), "{", `{"x5c":["AA"],`, 1)
	for name, tc := range map[string]struct {
		alg assertion.Alg
		raw string
	}{
		"private key":      {assertion.EdDSA, string(privJWK)},
		"RSA key":          {assertion.EdDSA, string(rsaJWK)},
		"P-384 for ES256":  {assertion.ES256, string(p384JWK)},
		"Ed25519 as ES256": {assertion.ES256, string(ed.pub.Canonical)},
		"alg mismatch":     {assertion.EdDSA, withAlg},
		"use enc":          {assertion.EdDSA, withUse},
		"x5c member":       {assertion.EdDSA, withX5c},
		"HS256 alg":        {"HS256", string(ed.pub.Canonical)},
		"empty":            {assertion.EdDSA, ""},
		"not json":         {assertion.EdDSA, "{"},
	} {
		if _, err := assertion.ParsePublicJWK(tc.alg, []byte(tc.raw)); !errors.Is(err, assertion.ErrInvalid) {
			t.Errorf("%s: err = %v", name, err)
		}
	}
}
