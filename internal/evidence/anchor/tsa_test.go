// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package anchor

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/evidence/anchor/anchortest"
)

func verifierFor(t testing.TB, ca *anchortest.CA) *TSAVerifier {
	t.Helper()
	v, err := NewTSAVerifier(ca.Chain)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func TestHR195_TimestampRequestAndToken(t *testing.T) {
	for _, rsaKey := range []bool{false, true} {
		ca := anchortest.NewCA(t, anchortest.CertOpts{RSA: rsaKey})
		fake := &anchortest.TSA{T: t, CA: ca}
		v := verifierFor(t, ca)
		c := &TSAClient{URL: anchortest.TSAURL, HTTP: fake, Verifier: v}
		signature := []byte("the anchor statement's signature")
		resp, ts, err := c.Timestamp(context.Background(), signature)
		if err != nil {
			t.Fatalf("rsa=%v: %v", rsaKey, err)
		}
		if !ts.Time.Equal(anchortest.TSANow) || ts.Serial.Int64() != 4242 || ts.Nonce == nil || !ts.Signer.Equal(ca.Cert) {
			t.Fatalf("timestamp = %+v", ts)
		}
		// The request: version 1, SHA-256 over the signature, a nonce, certReq.
		var req timeStampReq
		if err := unmarshalAll(fake.Request, &req); err != nil {
			t.Fatal(err)
		}
		if want := sha256.Sum256(signature); !bytes.Equal(req.MessageImprint.HashedMessage, want[:]) || !req.CertReq || req.Nonce.BitLen() < 120 {
			t.Fatalf("request = %+v", req)
		}
		// The kept response verifies again offline, only for that signature.
		if _, err := v.Verify(resp, signature); err != nil {
			t.Fatal(err)
		}
		if _, err := v.Verify(resp, []byte("another signature")); !errors.Is(err, ErrInvalidTimestamp) {
			t.Fatalf("token verified for other data: %v", err)
		}
		// A bare token verifies as well.
		token, err := ParseResponse(resp)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := v.Verify(token, signature); err != nil {
			t.Fatal(err)
		}
	}
	// Two requests never share a nonce.
	a, _ := NewTimestampRequest([]byte("s"))
	b, _ := NewTimestampRequest([]byte("s"))
	if a.Nonce.Cmp(b.Nonce) == 0 {
		t.Fatal("nonce repeated")
	}
}

// TestHR195_BadTimestampIsRejected: a token that does not verify (nonce,
// imprint, signature, attributes, signer certificate, chain, time, status)
// never counts.
func TestHR195_BadTimestampIsRejected(t *testing.T) {
	for name, tc := range map[string]struct {
		fault anchortest.TSAFault
		cert  anchortest.CertOpts
		other bool // the verifier trusts another authority
	}{
		"rejected status":     {fault: anchortest.TSAFault{Status: 2}},
		"wrong nonce":         {fault: anchortest.TSAFault{WrongNonce: true}},
		"no nonce":            {fault: anchortest.TSAFault{NoNonce: true}},
		"wrong imprint":       {fault: anchortest.TSAFault{WrongImprint: true}},
		"SHA-1 imprint":       {fault: anchortest.TSAFault{SHA1Imprint: true}},
		"bad signature":       {fault: anchortest.TSAFault{BadSignature: true}},
		"wrong digest":        {fault: anchortest.TSAFault{WrongDigest: true}},
		"no signed attrs":     {fault: anchortest.TSAFault{NoSignedAttrs: true}},
		"no content type":     {fault: anchortest.TSAFault{NoContentType: true}},
		"two signers":         {fault: anchortest.TSAFault{TwoSigners: true}},
		"no timestamping EKU": {cert: anchortest.CertOpts{NoEKU: true}},
		"non-critical EKU":    {cert: anchortest.CertOpts{NonCritical: true}},
		"extra EKU":           {cert: anchortest.CertOpts{ExtraEKU: true}},
		"expired certificate": {fault: anchortest.TSAFault{GenTime: anchortest.TSANow.Add(60 * 24 * time.Hour)}},
		"before certificate":  {fault: anchortest.TSAFault{GenTime: anchortest.TSANow.Add(-2 * time.Hour)}},
		"untrusted authority": {other: true},
	} {
		t.Run(name, func(t *testing.T) {
			ca := anchortest.NewCA(t, tc.cert)
			v := verifierFor(t, ca)
			if tc.other {
				v = verifierFor(t, anchortest.NewCA(t, anchortest.CertOpts{}))
			}
			fake := &anchortest.TSA{T: t, CA: ca, Fault: tc.fault}
			c := &TSAClient{URL: anchortest.TSAURL, HTTP: fake, Verifier: v}
			_, _, err := c.Timestamp(context.Background(), []byte("sig"))
			if !errors.Is(err, ErrInvalidTimestamp) {
				t.Fatalf("err = %v", err)
			}
			t.Log(err)
		})
	}
}

func TestTimestampWithoutEmbeddedCertificateAndValidity(t *testing.T) {
	ca := anchortest.NewCA(t, anchortest.CertOpts{})
	v := verifierFor(t, ca)
	fake := &anchortest.TSA{T: t, CA: ca, Fault: anchortest.TSAFault{NoCerts: true}}
	c := &TSAClient{URL: anchortest.TSAURL, HTTP: fake, Verifier: v}
	resp, _, err := c.Timestamp(context.Background(), []byte("sig"))
	if err != nil {
		t.Fatalf("signer from the configured chain: %v", err)
	}
	// Without the signer in the configured chain, the token cannot verify.
	rootOnly, _ := NewTSAVerifier([]*x509.Certificate{ca.Root})
	if _, err := rootOnly.Verify(resp, []byte("sig")); !errors.Is(err, ErrInvalidTimestamp) {
		t.Fatalf("unknown signer: %v", err)
	}
	// The authority's validity window (trusted root validFor) applies.
	now := anchortest.TSANow
	if _, err := v.WithValidity(now.Add(time.Minute), time.Time{}).Verify(resp, []byte("sig")); err == nil {
		t.Fatal("a timestamp before the authority's validity was accepted")
	}
	if _, err := v.WithValidity(time.Time{}, now.Add(-time.Minute)).Verify(resp, []byte("sig")); err == nil {
		t.Fatal("a timestamp after the authority's validity was accepted")
	}
	// Client-side refusals happen before any request.
	for name, c := range map[string]*TSAClient{
		"http":        {URL: "http://tsa.test", HTTP: fake, Verifier: v},
		"no verifier": {URL: anchortest.TSAURL, HTTP: fake},
	} {
		before := fake.Calls
		if _, _, err := c.Timestamp(context.Background(), []byte("sig")); err == nil || fake.Calls != before {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := NewTSAVerifier(nil); err == nil {
		t.Fatal("empty chain accepted")
	}
	if _, err := v.Verify([]byte{0x30, 0x00}, []byte("sig")); !errors.Is(err, ErrInvalidTimestamp) {
		t.Fatalf("empty sequence: %v", err)
	}
}

func TestParseCertificateChain(t *testing.T) {
	ca := anchortest.NewCA(t, anchortest.CertOpts{})
	var pemData []byte
	for _, c := range ca.Chain {
		pemData = append(pemData, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})...)
	}
	chain, err := ParseCertificateChain(pemData)
	if err != nil || len(chain) != 2 || !chain[1].Equal(ca.Root) {
		t.Fatalf("chain: %v", err)
	}
	for name, b := range map[string][]byte{
		"empty":       nil,
		"private key": pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte{1}}),
		"trailing":    append(bytes.Clone(pemData), "junk"...),
		"bad cert":    pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte{1}}),
	} {
		if _, err := ParseCertificateChain(b); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

// TestHR195_RecordedTimestampVerifies checks the verifier against RFC 3161
// responses recorded from Sigstore's staging timestamp authority (ECDSA
// P-384 signer, with and without the embedded certificate), over the
// bundle's signature as Sigstore timestamps it.
func TestHR195_RecordedTimestampVerifies(t *testing.T) {
	v, err := NewTSAVerifier(recordedTSAChain(t))
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range recordedCases {
		t.Run(name, func(t *testing.T) {
			b := recordedBundleFor(t, name)
			resp := b.VerificationMaterial.TimestampVerificationData.RFC3161Timestamps[0].SignedTimestamp
			sig := b.MessageSignature.Signature
			ts, err := v.Verify(resp, sig)
			if err != nil {
				t.Fatal(err)
			}
			if ts.Time.Year() != 2025 || ts.Signer.Subject.CommonName != "sigstore-tsa" {
				t.Fatalf("timestamp %v by %s", ts.Time, ts.Signer.Subject)
			}
			if _, err := v.Verify(resp, append(bytes.Clone(sig), 0)); !errors.Is(err, ErrInvalidTimestamp) {
				t.Fatalf("other data: %v", err)
			}
			bad := bytes.Clone(resp)
			bad[len(bad)-5] ^= 1 // inside the CMS signature
			if _, err := v.Verify(bad, sig); !errors.Is(err, ErrInvalidTimestamp) {
				t.Fatalf("altered token: %v", err)
			}
			other := verifierFor(t, anchortest.NewCA(t, anchortest.CertOpts{}))
			if _, err := other.Verify(resp, sig); !errors.Is(err, ErrInvalidTimestamp) {
				t.Fatalf("another authority: %v", err)
			}
		})
	}
}

// FuzzTimestampToken: arbitrary tokens and responses never panic, fail only
// with ErrInvalidTimestamp, and never verify against the test authority
// unless they are its own.
func FuzzTimestampToken(f *testing.F) {
	recorded, err := NewTSAVerifier(recordedTSAChain(f))
	if err != nil {
		f.Fatal(err)
	}
	b := recordedBundleFor(f, recordedCases[0])
	sig := b.MessageSignature.Signature
	f.Add(b.VerificationMaterial.TimestampVerificationData.RFC3161Timestamps[0].SignedTimestamp)
	ca := anchortest.NewCA(f, anchortest.CertOpts{})
	fake := &anchortest.TSA{T: f, CA: ca}
	imprint := sha256.Sum256(sig)
	token := fake.Token(imprint[:], big.NewInt(7))
	f.Add(token)
	f.Add(fake.Response(token))
	f.Add([]byte{0x30, 0x03, 0x02, 0x01, 0x00})
	own := verifierFor(f, ca)
	f.Fuzz(func(t *testing.T, data []byte) {
		for _, v := range []*TSAVerifier{recorded, own} {
			if _, err := v.Verify(data, sig); err != nil && !errors.Is(err, ErrInvalidTimestamp) {
				t.Fatalf("error type: %v", err)
			}
		}
		if _, err := ParseResponse(data); err != nil && !errors.Is(err, ErrInvalidTimestamp) {
			t.Fatalf("error type: %v", err)
		}
	})
}
