// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pap_test

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/identity/pap"
	"github.com/katocxl/pantherclaw/internal/platform/crypto/jws"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

const (
	issuer = "https://authority.test"
	url    = "https://gateway.test/v1/refunds"
	nonce  = "bm9uY2Utbm9uY2Utbm9uY2Utbm9uY2U"
)

var now = time.Unix(1791457200, 0)

type world struct {
	signer   *jws.Signer
	verifier *jws.Verifier
	key      ed25519.PrivateKey
	inst     pap.Instance
}

func newWorld(t *testing.T) world {
	t.Helper()
	_, authority, _ := ed25519.GenerateKey(nil)
	signer, err := jws.NewSigner("wt-1", authority)
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := jws.NewVerifier(pap.TokenType, map[string]ed25519.PublicKey{"wt-1": signer.Public()})
	if err != nil {
		t.Fatal(err)
	}
	_, key, _ := ed25519.GenerateKey(nil)
	return world{signer: signer, verifier: verifier, key: key, inst: pap.Instance{
		Org: ids.New[ids.Org](), Agent: ids.NewV7(), Instance: ids.NewV7(),
	}}
}

func (w world) token(t *testing.T, key ed25519.PrivateKey) string {
	t.Helper()
	pub, _ := key.Public().(ed25519.PublicKey)
	compact, _, err := pap.Issue(w.signer, issuer, pap.Token{
		Instance: w.inst, Environment: ids.NewV7(), JKT: jws.Thumbprint(pub), Level: 1,
	}, now, time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	return compact
}

func proof(t *testing.T, key ed25519.PrivateKey, p pap.ProofParams) string {
	t.Helper()
	if p.Method == "" {
		p.Method = "POST"
	}
	if p.URL == "" {
		p.URL = url
	}
	if p.Nonce == "" {
		p.Nonce = nonce
	}
	if p.Now.IsZero() {
		p.Now = now
	}
	s, err := pap.NewProof(key, p)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func request(token string, body []byte) pap.Request {
	return pap.Request{Method: "POST", URL: url, BodySHA256: sha256.Sum256(body), Token: token}
}

func wantCode(t *testing.T, name string, err error, code pap.Code) {
	t.Helper()
	if !errors.Is(err, pap.Err(code)) {
		t.Errorf("%s: err = %v, want %s", name, err, code)
	}
}

func TestVerifyRequestAcceptsAValidProof(t *testing.T) {
	w := newWorld(t)
	body := []byte(`{"amount":"30.00"}`)
	tok := w.token(t, w.key)
	c, err := pap.VerifyRequest(w.verifier, issuer, request(tok, body), proof(t, w.key, pap.ProofParams{Body: body, Token: tok}), now)
	if err != nil {
		t.Fatal(err)
	}
	got, ok := c.Token()
	pub, _ := w.key.Public().(ed25519.PublicKey)
	if !ok || got.Instance != w.inst || c.JKT() != jws.Thumbprint(pub) || c.Nonce() != nonce || len(c.JTI()) < 22 {
		t.Fatalf("checked = %+v / %+v", c, got)
	}
}

// TestT032_StolenTokenWithoutKeyIsUseless: a token is bound to its key
// (cnf.jkt); a proof signed with any other key fails (PAP-1 §4 step 3).
func TestT032_StolenTokenWithoutKeyIsUseless(t *testing.T) {
	w := newWorld(t)
	tok := w.token(t, w.key)
	_, thief, _ := ed25519.GenerateKey(nil)
	_, err := pap.VerifyRequest(w.verifier, issuer, request(tok, nil), proof(t, thief, pap.ProofParams{Token: tok}), now)
	wantCode(t, "thief's key", err, pap.CodeKeyMismatch)
}

// TestT032_ProofCoversExactlyThisRequest: method, target URI, token and raw
// body are all bound (PAP-1 §4 step 4).
func TestT032_ProofCoversExactlyThisRequest(t *testing.T) {
	w := newWorld(t)
	tok, other := w.token(t, w.key), w.token(t, w.key)
	body := []byte(`{"amount":"30.00"}`)
	for name, tc := range map[string]struct {
		p    pap.ProofParams
		req  pap.Request
		code pap.Code
	}{
		"wrong htm":          {pap.ProofParams{Method: "GET", Body: body, Token: tok}, request(tok, body), pap.CodeInvalidProof},
		"other host":         {pap.ProofParams{URL: "https://evil.test/v1/refunds", Body: body, Token: tok}, request(tok, body), pap.CodeInvalidProof},
		"other path":         {pap.ProofParams{URL: "https://gateway.test/v1/payouts", Body: body, Token: tok}, request(tok, body), pap.CodeInvalidProof},
		"query in htu":       {pap.ProofParams{URL: url + "?amount=1", Body: body, Token: tok}, request(tok, body), pap.CodeInvalidProof},
		"ath of other token": {pap.ProofParams{Body: body, Token: other}, request(tok, body), pap.CodeInvalidProof},
		"ath without token":  {pap.ProofParams{Body: body, Token: tok}, request("", body), pap.CodeInvalidProof},
		"body changed":       {pap.ProofParams{Body: body, Token: tok}, request(tok, []byte(`{"amount":"3000.00"}`)), pap.CodeBodyHashMismatch},
		"old proof":          {pap.ProofParams{Body: body, Token: tok, Now: now.Add(-10 * time.Minute)}, request(tok, body), pap.CodeInvalidProof},
		"future proof":       {pap.ProofParams{Body: body, Token: tok, Now: now.Add(5 * time.Minute)}, request(tok, body), pap.CodeInvalidProof},
	} {
		_, err := pap.VerifyRequest(w.verifier, issuer, tc.req, proof(t, w.key, tc.p), now)
		wantCode(t, name, err, tc.code)
	}
	// Scheme and host compare case-insensitively; the path does not.
	if _, err := pap.VerifyRequest(w.verifier, issuer, request(tok, body),
		proof(t, w.key, pap.ProofParams{URL: "HTTPS://Gateway.Test/v1/refunds", Body: body, Token: tok}), now); err != nil {
		t.Errorf("case-insensitive host: %v", err)
	}
}

// TestHR091_BodyIsHashedRawAndNoncesAreRequired: the hash covers the exact
// bytes, so a re-encoded body fails; a proof without a nonce asks for one.
func TestHR091_BodyIsHashedRawAndNoncesAreRequired(t *testing.T) {
	w := newWorld(t)
	tok := w.token(t, w.key)
	signed := []byte(`{"amount":"30.00"}`)
	reencoded := []byte(`{"amount": "30.00"}`)
	_, err := pap.VerifyRequest(w.verifier, issuer, request(tok, reencoded), proof(t, w.key, pap.ProofParams{Body: signed, Token: tok}), now)
	wantCode(t, "re-encoded body", err, pap.CodeBodyHashMismatch)
	for name, n := range map[string]string{"short nonce": "abc", "bad chars": "nonce nonce nonce nonce nonce"} {
		_, err := pap.VerifyRequest(w.verifier, issuer, request(tok, signed), proof(t, w.key, pap.ProofParams{Body: signed, Token: tok, Nonce: n}), now)
		wantCode(t, name, err, pap.CodeUseNonce)
	}
	if !pap.ValidNonce(nonce) || pap.ValidNonce("") {
		t.Fatal("nonce shape")
	}
}

// TestHR090_NothingUnverifiedReachesTheReplayStore: every failure returns
// a zero Checked (no jti to record), and a key-only proof yields a key but
// no identity.
func TestHR090_NothingUnverifiedReachesTheReplayStore(t *testing.T) {
	w := newWorld(t)
	_, other, _ := ed25519.GenerateKey(nil)
	tok := w.token(t, w.key)
	c, err := pap.VerifyRequest(w.verifier, issuer, request(tok, nil), proof(t, other, pap.ProofParams{Token: tok}), now)
	if err == nil || c.JTI() != "" || c.JKT() != "" {
		t.Fatalf("failed verification returned %+v, %v", c, err)
	}
	keyOnly, err := pap.VerifyRequest(w.verifier, issuer, request("", nil), proof(t, w.key, pap.ProofParams{}), now)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := keyOnly.Token(); ok || keyOnly.JTI() == "" {
		t.Fatal("a key-only proof must carry a key and a jti but no identity")
	}
}

func segment(v string) string { return base64.RawURLEncoding.EncodeToString([]byte(v)) }

// TestHR095_ProofAlgorithmsAndKeysArePinned: only EdDSA with an embedded
// public Ed25519 key; alg none, HMAC, other header members and private key
// material are rejected.
func TestHR095_ProofAlgorithmsAndKeysArePinned(t *testing.T) {
	w := newWorld(t)
	pub, _ := w.key.Public().(ed25519.PublicKey)
	x := base64.RawURLEncoding.EncodeToString(pub)
	good := proof(t, w.key, pap.ProofParams{})
	parts := strings.Split(good, ".")
	for name, header := range map[string]string{
		"alg none":       `{"alg":"none","typ":"pap-proof+jwt","jwk":{"kty":"OKP","crv":"Ed25519","x":"` + x + `"}}`,
		"HS256":          `{"alg":"HS256","typ":"pap-proof+jwt","jwk":{"kty":"OKP","crv":"Ed25519","x":"` + x + `"}}`,
		"wrong typ":      `{"alg":"EdDSA","typ":"JWT","jwk":{"kty":"OKP","crv":"Ed25519","x":"` + x + `"}}`,
		"kid header":     `{"alg":"EdDSA","typ":"pap-proof+jwt","kid":"k","jwk":{"kty":"OKP","crv":"Ed25519","x":"` + x + `"}}`,
		"jku header":     `{"alg":"EdDSA","typ":"pap-proof+jwt","jku":"https://evil.test","jwk":{"kty":"OKP","crv":"Ed25519","x":"` + x + `"}}`,
		"private jwk":    `{"alg":"EdDSA","typ":"pap-proof+jwt","jwk":{"kty":"OKP","crv":"Ed25519","x":"` + x + `","d":"` + x + `"}}`,
		"P-256 jwk":      `{"alg":"EdDSA","typ":"pap-proof+jwt","jwk":{"kty":"EC","crv":"P-256","x":"` + x + `"}}`,
		"duplicate alg":  `{"alg":"EdDSA","alg":"none","typ":"pap-proof+jwt","jwk":{"kty":"OKP","crv":"Ed25519","x":"` + x + `"}}`,
		"crit extension": `{"alg":"EdDSA","typ":"pap-proof+jwt","crit":["b64"],"b64":false,"jwk":{"kty":"OKP","crv":"Ed25519","x":"` + x + `"}}`,
	} {
		forged := segment(header) + "." + parts[1] + "." + parts[2]
		_, err := pap.VerifyRequest(w.verifier, issuer, request("", nil), forged, now)
		wantCode(t, name, err, pap.CodeInvalidProof)
	}
	tampered := parts[0] + "." + segment(`{"htm":"POST","htu":"`+url+`","iat":1791457200,"jti":"AAAAAAAAAAAAAAAAAAAAAA","bh":"x","nonce":"`+nonce+`"}`) + "." + parts[2]
	_, err := pap.VerifyRequest(w.verifier, issuer, request("", nil), tampered, now)
	wantCode(t, "payload swapped under the signature", err, pap.CodeInvalidProof)
}

// TestT032_TokenSubstitutionAndLifetime: only workload tokens from this
// Authority verify; other JWS types, issuers and expired tokens fail.
func TestT032_TokenSubstitutionAndLifetime(t *testing.T) {
	w := newWorld(t)
	tok := w.token(t, w.key)
	if _, err := pap.VerifyToken(w.verifier, issuer, tok, now); err != nil {
		t.Fatal(err)
	}
	permit, err := w.signer.Sign("pap-permit+jwt", []byte(`{"iss":"`+issuer+`"}`))
	if err != nil {
		t.Fatal(err)
	}
	_, err = pap.VerifyToken(w.verifier, issuer, permit, now)
	wantCode(t, "permit as workload token", err, pap.CodeInvalidToken)
	_, err = pap.VerifyToken(w.verifier, "https://other.test", tok, now)
	wantCode(t, "other issuer", err, pap.CodeInvalidToken)
	_, err = pap.VerifyToken(w.verifier, issuer, tok, now.Add(pap.MaxTokenTTL+2*pap.Leeway))
	wantCode(t, "expired", err, pap.CodeTokenExpired)
	_, err = pap.VerifyToken(w.verifier, issuer, tok, now.Add(-2*pap.Leeway))
	wantCode(t, "not yet valid", err, pap.CodeInvalidToken)
	_, otherAuthority, _ := ed25519.GenerateKey(nil)
	forger, _ := jws.NewSigner("wt-1", otherAuthority)
	forged, _, _ := pap.Issue(forger, issuer, pap.Token{Instance: w.inst, Environment: ids.NewV7(), JKT: strings.Repeat("A", 43), Level: 2}, now, time.Time{})
	_, err = pap.VerifyToken(w.verifier, issuer, forged, now)
	wantCode(t, "same kid, other key", err, pap.CodeInvalidToken)
}

// TestHR143_TokenNeverOutlivesItsAttestation: an L2 token expires with the
// attestation behind it.
func TestHR143_TokenNeverOutlivesItsAttestation(t *testing.T) {
	w := newWorld(t)
	att := now.Add(4 * time.Minute)
	_, tok, err := pap.Issue(w.signer, issuer, pap.Token{
		Instance: w.inst, Environment: ids.NewV7(), JKT: strings.Repeat("A", 43), Level: 2,
	}, now, att)
	if err != nil || !tok.ExpiresAt.Equal(att) {
		t.Fatalf("expiry %v (err %v), want %v", tok.ExpiresAt, err, att)
	}
	_, _, err = pap.Issue(w.signer, issuer, pap.Token{
		Instance: w.inst, Environment: ids.NewV7(), JKT: strings.Repeat("A", 43), Level: 2,
	}, now, now.Add(-time.Second))
	wantCode(t, "lapsed attestation", err, pap.CodeAttestationLow)
}

func TestInstanceIdentifiers(t *testing.T) {
	w := newWorld(t)
	got, err := pap.ParseInstance(w.inst.String())
	if err != nil || got != w.inst {
		t.Fatalf("round trip: %v, %v", got, err)
	}
	for _, s := range []string{
		"", strings.ToUpper(w.inst.String()), "pc:org/x/agent/y/inst/z",
		"pc:org/" + w.inst.Org.String() + "/agent/00000000-0000-0000-0000-000000000000/inst/" + w.inst.Instance.String(),
	} {
		if _, err := pap.ParseInstance(s); err == nil {
			t.Errorf("ParseInstance(%q) accepted", s)
		}
	}
}

func TestNonceSlotsAndLifetime(t *testing.T) {
	m := pap.NonceMinute(now)
	if pap.Slot(m) != int16(m%10) || pap.Slot(m+10) != pap.Slot(m) {
		t.Fatal("slot ring")
	}
	issued := time.Unix(m*60, 0)
	if pap.NonceExpired(m, issued.Add(5*time.Minute)) || !pap.NonceExpired(m, issued.Add(6*time.Minute)) {
		t.Fatal("a nonce lives until 6 minutes after its minute starts")
	}
}

// FuzzProofVerify: arbitrary proofs never panic and never verify.
func FuzzProofVerify(f *testing.F) {
	_, key, _ := ed25519.GenerateKey(nil)
	good, _ := pap.NewProof(key, pap.ProofParams{Method: "POST", URL: url, Nonce: nonce, Now: now})
	f.Add(good)
	f.Add("e30.e30.")
	f.Fuzz(func(t *testing.T, s string) {
		_, err := pap.VerifyRequest(nil, issuer, pap.Request{Method: "POST", URL: url, BodySHA256: [32]byte{1}}, s, now)
		if err == nil {
			t.Fatalf("proof %q verified against a body hash nobody signed", s)
		}
	})
}

// FuzzWorkloadToken: arbitrary tokens never panic and never verify.
func FuzzWorkloadToken(f *testing.F) {
	_, authority, _ := ed25519.GenerateKey(nil)
	s, _ := jws.NewSigner("wt-1", authority)
	v, _ := jws.NewVerifier(pap.TokenType, map[string]ed25519.PublicKey{"wt-1": s.Public()})
	f.Add("e30.e30.")
	f.Fuzz(func(t *testing.T, tok string) {
		if _, err := pap.VerifyToken(v, issuer, tok, now); err == nil {
			t.Fatalf("forged token %q verified", tok)
		}
	})
}
