// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package anchor

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net/http"
	"testing"
	"time"
)

var tsaNow = time.Date(2026, 10, 10, 9, 0, 5, 0, time.UTC)

// testCA is a test certificate authority with a timestamping certificate.
type testCA struct {
	root     *x509.Certificate
	rootKey  crypto.Signer
	cert     *x509.Certificate
	certKey  crypto.Signer
	chain    []*x509.Certificate // leaf first, root last
	verifier *TSAVerifier
}

type certOpts struct {
	rsa         bool
	noEKU       bool
	nonCritical bool
	extraEKU    bool
	notAfter    time.Time
}

func newTestCA(t testing.TB, o certOpts) *testCA {
	t.Helper()
	rootKey, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	rootTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test tsa root"},
		NotBefore: tsaNow.Add(-24 * time.Hour), NotAfter: tsaNow.Add(365 * 24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTmpl, rootTmpl, &rootKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	root, _ := x509.ParseCertificate(rootDER)

	var certKey crypto.Signer
	if o.rsa {
		certKey, _ = rsa.GenerateKey(rand.Reader, 2048)
	} else {
		certKey, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	}
	notAfter := o.notAfter
	if notAfter.IsZero() {
		notAfter = tsaNow.Add(30 * 24 * time.Hour)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(77), Subject: pkix.Name{CommonName: "test tsa"},
		NotBefore: tsaNow.Add(-time.Hour), NotAfter: notAfter, KeyUsage: x509.KeyUsageDigitalSignature,
		SubjectKeyId: []byte{1, 2, 3, 4},
	}
	if !o.noEKU {
		ekus := []asn1.ObjectIdentifier{{1, 3, 6, 1, 5, 5, 7, 3, 8}}
		if o.extraEKU {
			ekus = append(ekus, asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 3})
		}
		v, _ := asn1.Marshal(ekus)
		tmpl.ExtraExtensions = []pkix.Extension{{Id: oidExtKeyUsage, Critical: !o.nonCritical, Value: v}}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, root, certKey.Public(), rootKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	ca := &testCA{root: root, rootKey: rootKey, cert: cert, certKey: certKey, chain: []*x509.Certificate{cert, root}}
	if ca.verifier, err = NewTSAVerifier(ca.chain); err != nil {
		t.Fatal(err)
	}
	return ca
}

// tsaFault breaks one part of the fake authority's answer.
type tsaFault struct {
	status        int  // PKIStatus (0 when unset)
	wrongNonce    bool // answers with another nonce
	noNonce       bool
	wrongImprint  bool // timestamps other data
	badSignature  bool
	wrongDigest   bool // messageDigest attribute of other content
	noSignedAttrs bool
	noContentType bool
	twoSigners    bool
	noCerts       bool // the token does not embed the signer's certificate
	sha1Imprint   bool
	genTime       time.Time
}

// fakeTSA is a local RFC 3161 authority: it parses the request and builds a
// CMS SignedData token with a small encoder (RFC 5652 §5).
type fakeTSA struct {
	t       testing.TB
	ca      *testCA
	fault   tsaFault
	calls   int
	request []byte
}

type attributeOut struct {
	Type   asn1.ObjectIdentifier
	Values asn1.RawValue
}

func mustMarshal(t testing.TB, v any, params ...string) []byte {
	t.Helper()
	var (
		b   []byte
		err error
	)
	if len(params) > 0 {
		b, err = asn1.MarshalWithParams(v, params[0])
	} else {
		b, err = asn1.Marshal(v)
	}
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func setOf(t testing.TB, elems ...[]byte) []byte {
	t.Helper()
	var raws []asn1.RawValue
	for _, e := range elems {
		raws = append(raws, asn1.RawValue{FullBytes: e})
	}
	return mustMarshal(t, raws, "set")
}

func (f *fakeTSA) attribute(oid asn1.ObjectIdentifier, value []byte) []byte {
	return mustMarshal(f.t, attributeOut{oid, asn1.RawValue{FullBytes: setOf(f.t, value)}})
}

// token builds a TimeStampToken for the imprint and nonce.
func (f *fakeTSA) token(imprint []byte, nonce *big.Int) []byte {
	t, ca, fault := f.t, f.ca, f.fault
	hashAlg := pkix.AlgorithmIdentifier{Algorithm: oidSHA256, Parameters: asn1.NullRawValue}
	if fault.sha1Imprint {
		hashAlg = pkix.AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{1, 3, 14, 3, 2, 26}}
	}
	if fault.wrongImprint {
		imprint = bytes.Repeat([]byte{9}, 32)
	}
	if fault.wrongNonce {
		nonce = new(big.Int).Add(nonce, big.NewInt(1))
	}
	if fault.noNonce {
		nonce = nil
	}
	genTime := tsaNow
	if !fault.genTime.IsZero() {
		genTime = fault.genTime
	}
	type tstInfoOut struct {
		Version        int
		Policy         asn1.ObjectIdentifier
		MessageImprint messageImprint
		SerialNumber   *big.Int
		GenTime        time.Time `asn1:"generalized"`
		Accuracy       accuracy  `asn1:"optional"`
		Nonce          *big.Int  `asn1:"optional"`
	}
	content := mustMarshal(t, tstInfoOut{
		Version: 1, Policy: asn1.ObjectIdentifier{1, 2, 3, 4}, SerialNumber: big.NewInt(4242),
		MessageImprint: messageImprint{HashAlgorithm: hashAlg, HashedMessage: imprint},
		GenTime:        genTime, Accuracy: accuracy{Seconds: 1}, Nonce: nonce,
	})

	digest := sha256.Sum256(content)
	if fault.wrongDigest {
		digest = sha256.Sum256([]byte("other"))
	}
	var attrs [][]byte
	if !fault.noContentType {
		attrs = append(attrs, f.attribute(oidContentType, mustMarshal(t, oidTSTInfo)))
	}
	attrs = append(attrs, f.attribute(oidMessageDigest, mustMarshal(t, digest[:])))
	signedAttrs := setOf(t, attrs...)

	h := sha256.Sum256(signedAttrs)
	var (
		sig    []byte
		sigAlg pkix.AlgorithmIdentifier
		err    error
	)
	if _, ok := ca.certKey.(*rsa.PrivateKey); ok {
		sig, err = ca.certKey.Sign(rand.Reader, h[:], crypto.SHA256)
		sigAlg = pkix.AlgorithmIdentifier{Algorithm: oidRSAEncryption, Parameters: asn1.NullRawValue}
	} else {
		sig, err = ca.certKey.Sign(rand.Reader, h[:], crypto.SHA256)
		sigAlg = pkix.AlgorithmIdentifier{Algorithm: oidECDSAWithSHA256}
	}
	if err != nil {
		t.Fatal(err)
	}
	if fault.badSignature {
		h2 := sha256.Sum256([]byte("not the attributes"))
		sig, _ = ca.certKey.Sign(rand.Reader, h2[:], crypto.SHA256)
	}
	type signerInfoOut struct {
		Version            int
		SID                asn1.RawValue
		DigestAlgorithm    pkix.AlgorithmIdentifier
		SignedAttrs        asn1.RawValue `asn1:"optional"`
		SignatureAlgorithm pkix.AlgorithmIdentifier
		Signature          []byte
	}
	implicit := bytes.Clone(signedAttrs)
	implicit[0] = 0xa0 // [0] IMPLICIT
	si := signerInfoOut{
		Version:         1,
		SID:             asn1.RawValue{FullBytes: mustMarshal(t, issuerAndSerial{asn1.RawValue{FullBytes: ca.cert.RawIssuer}, ca.cert.SerialNumber})},
		DigestAlgorithm: pkix.AlgorithmIdentifier{Algorithm: oidSHA256}, SignedAttrs: asn1.RawValue{FullBytes: implicit},
		SignatureAlgorithm: sigAlg, Signature: sig,
	}
	if fault.noSignedAttrs {
		si.SignedAttrs = asn1.RawValue{}
	}
	signers := [][]byte{mustMarshal(t, si)}
	if fault.twoSigners {
		si.Version = 3
		signers = append(signers, mustMarshal(t, si))
	}
	// encoding/asn1 ignores `explicit` on a RawValue: wrap [0] by hand.
	wrap0 := func(inner []byte) asn1.RawValue {
		return asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: inner}
	}
	type encapOut struct {
		EContentType asn1.ObjectIdentifier
		EContent     asn1.RawValue
	}
	type signedDataOut struct {
		Version          int
		DigestAlgorithms asn1.RawValue
		EncapContentInfo encapOut
		Certificates     asn1.RawValue `asn1:"optional"`
		SignerInfos      asn1.RawValue
	}
	sd := signedDataOut{
		Version:          3,
		DigestAlgorithms: asn1.RawValue{FullBytes: setOf(t, mustMarshal(t, pkix.AlgorithmIdentifier{Algorithm: oidSHA256}))},
		EncapContentInfo: encapOut{oidTSTInfo, wrap0(mustMarshal(t, content))},
		SignerInfos:      asn1.RawValue{FullBytes: setOf(t, signers...)},
	}
	if !fault.noCerts {
		sd.Certificates = asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: ca.cert.Raw}
	}
	type contentInfoOut struct {
		ContentType asn1.ObjectIdentifier
		Content     asn1.RawValue
	}
	return mustMarshal(t, contentInfoOut{oidSignedData, wrap0(mustMarshal(t, sd))})
}

// acceptTimestampRequest checks a request as an authority would: version 1,
// a SHA-256 imprint, a nonce and certReq.
func acceptTimestampRequest(body []byte) (timeStampReq, bool) {
	var r timeStampReq
	err := unmarshalAll(body, &r)
	return r, err == nil && r.Version == 1 && r.CertReq && r.Nonce != nil &&
		r.MessageImprint.HashAlgorithm.Algorithm.Equal(oidSHA256) && len(r.MessageImprint.HashedMessage) == 32
}

func (f *fakeTSA) Do(req *http.Request) (*http.Response, error) {
	f.calls++
	if req.Method != http.MethodPost || req.Header.Get("Content-Type") != "application/timestamp-query" || req.URL.Host != "tsa.test" {
		return reply(http.StatusBadRequest, nil), nil
	}
	body, _ := io.ReadAll(req.Body)
	f.request = body
	r, ok := acceptTimestampRequest(body)
	if !ok {
		return reply(http.StatusBadRequest, nil), nil
	}
	type respOut struct {
		Status pkiStatusInfo
		Token  asn1.RawValue `asn1:"optional"`
	}
	out := respOut{Status: pkiStatusInfo{Status: f.fault.status}}
	if f.fault.status == 0 {
		out.Token = asn1.RawValue{FullBytes: f.token(r.MessageImprint.HashedMessage, r.Nonce)}
	}
	return reply(http.StatusOK, mustMarshal(f.t, out)), nil
}

func TestHR195_TimestampRequestAndToken(t *testing.T) {
	for _, rsaKey := range []bool{false, true} {
		ca := newTestCA(t, certOpts{rsa: rsaKey})
		fake := &fakeTSA{t: t, ca: ca}
		c := &TSAClient{URL: "https://tsa.test/api/v1/timestamp", HTTP: fake, Verifier: ca.verifier}
		signature := []byte("the anchor statement's signature")
		token, ts, err := c.Timestamp(context.Background(), signature)
		if err != nil {
			t.Fatalf("rsa=%v: %v", rsaKey, err)
		}
		if !ts.Time.Equal(tsaNow) || ts.Serial.Int64() != 4242 || ts.Nonce == nil || !ts.Signer.Equal(ca.cert) {
			t.Fatalf("timestamp = %+v", ts)
		}
		// The request: version 1, SHA-256 over the signature, a nonce, certReq.
		var req timeStampReq
		if err := unmarshalAll(fake.request, &req); err != nil {
			t.Fatal(err)
		}
		if want := sha256.Sum256(signature); !bytes.Equal(req.MessageImprint.HashedMessage, want[:]) || !req.CertReq || req.Nonce.BitLen() < 120 {
			t.Fatalf("request = %+v", req)
		}
		// The kept token verifies again offline, only for that signature.
		if _, err := ca.verifier.Verify(token, signature); err != nil {
			t.Fatal(err)
		}
		if _, err := ca.verifier.Verify(token, []byte("another signature")); !errors.Is(err, ErrInvalidTimestamp) {
			t.Fatalf("token verified for other data: %v", err)
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
		fault tsaFault
		cert  certOpts
		other bool // the verifier trusts another authority
	}{
		"rejected status":     {fault: tsaFault{status: 2}},
		"wrong nonce":         {fault: tsaFault{wrongNonce: true}},
		"no nonce":            {fault: tsaFault{noNonce: true}},
		"wrong imprint":       {fault: tsaFault{wrongImprint: true}},
		"SHA-1 imprint":       {fault: tsaFault{sha1Imprint: true}},
		"bad signature":       {fault: tsaFault{badSignature: true}},
		"wrong digest":        {fault: tsaFault{wrongDigest: true}},
		"no signed attrs":     {fault: tsaFault{noSignedAttrs: true}},
		"no content type":     {fault: tsaFault{noContentType: true}},
		"two signers":         {fault: tsaFault{twoSigners: true}},
		"no timestamping EKU": {cert: certOpts{noEKU: true}},
		"non-critical EKU":    {cert: certOpts{nonCritical: true}},
		"extra EKU":           {cert: certOpts{extraEKU: true}},
		"expired certificate": {fault: tsaFault{genTime: tsaNow.Add(60 * 24 * time.Hour)}},
		"before certificate":  {fault: tsaFault{genTime: tsaNow.Add(-2 * time.Hour)}},
		"untrusted authority": {other: true},
	} {
		t.Run(name, func(t *testing.T) {
			ca := newTestCA(t, tc.cert)
			v := ca.verifier
			if tc.other {
				v = newTestCA(t, certOpts{}).verifier
			}
			fake := &fakeTSA{t: t, ca: ca, fault: tc.fault}
			c := &TSAClient{URL: "https://tsa.test", HTTP: fake, Verifier: v}
			_, _, err := c.Timestamp(context.Background(), []byte("sig"))
			if !errors.Is(err, ErrInvalidTimestamp) {
				t.Fatalf("err = %v", err)
			}
			t.Log(err)
		})
	}
}

func TestTimestampWithoutEmbeddedCertificateAndValidity(t *testing.T) {
	ca := newTestCA(t, certOpts{})
	fake := &fakeTSA{t: t, ca: ca, fault: tsaFault{noCerts: true}}
	c := &TSAClient{URL: "https://tsa.test", HTTP: fake, Verifier: ca.verifier}
	token, _, err := c.Timestamp(context.Background(), []byte("sig"))
	if err != nil {
		t.Fatalf("signer from the configured chain: %v", err)
	}
	// Without the signer in the configured chain, the token cannot verify.
	rootOnly, _ := NewTSAVerifier([]*x509.Certificate{ca.root})
	if _, err := rootOnly.Verify(token, []byte("sig")); !errors.Is(err, ErrInvalidTimestamp) {
		t.Fatalf("unknown signer: %v", err)
	}
	// The authority's validity window (trusted root validFor) applies.
	if _, err := ca.verifier.WithValidity(tsaNow.Add(time.Minute), time.Time{}).Verify(token, []byte("sig")); err == nil {
		t.Fatal("a timestamp before the authority's validity was accepted")
	}
	if _, err := ca.verifier.WithValidity(time.Time{}, tsaNow.Add(-time.Minute)).Verify(token, []byte("sig")); err == nil {
		t.Fatal("a timestamp after the authority's validity was accepted")
	}
	// Client-side refusals happen before any request.
	for name, c := range map[string]*TSAClient{
		"http":        {URL: "http://tsa.test", HTTP: fake, Verifier: ca.verifier},
		"no verifier": {URL: "https://tsa.test", HTTP: fake},
	} {
		before := fake.calls
		if _, _, err := c.Timestamp(context.Background(), []byte("sig")); err == nil || fake.calls != before {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := NewTSAVerifier(nil); err == nil {
		t.Fatal("empty chain accepted")
	}
}

func TestParseCertificateChain(t *testing.T) {
	ca := newTestCA(t, certOpts{})
	var pemData []byte
	for _, c := range ca.chain {
		pemData = append(pemData, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})...)
	}
	chain, err := ParseCertificateChain(pemData)
	if err != nil || len(chain) != 2 || !chain[1].Equal(ca.root) {
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
// tokens recorded from Sigstore's staging timestamp authority (ECDSA P-384
// signer, with and without the embedded certificate), over the bundle's
// signature as Sigstore timestamps it.
func TestHR195_RecordedTimestampVerifies(t *testing.T) {
	v, err := NewTSAVerifier(recordedTSAChain(t))
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range recordedCases {
		t.Run(name, func(t *testing.T) {
			b := recordedBundleFor(t, name)
			token := b.VerificationMaterial.TimestampVerificationData.RFC3161Timestamps[0].SignedTimestamp
			sig := b.MessageSignature.Signature
			ts, err := v.Verify(token, sig)
			if err != nil {
				t.Fatal(err)
			}
			if ts.Time.Year() != 2025 || ts.Signer.Subject.CommonName != "sigstore-tsa" {
				t.Fatalf("timestamp %v by %s", ts.Time, ts.Signer.Subject)
			}
			if _, err := v.Verify(token, append(bytes.Clone(sig), 0)); !errors.Is(err, ErrInvalidTimestamp) {
				t.Fatalf("other data: %v", err)
			}
			bad := bytes.Clone(token)
			bad[len(bad)-5] ^= 1 // inside the CMS signature
			if _, err := v.Verify(bad, sig); !errors.Is(err, ErrInvalidTimestamp) {
				t.Fatalf("altered token: %v", err)
			}
			if _, err := newTestCA(t, certOpts{}).verifier.Verify(token, sig); !errors.Is(err, ErrInvalidTimestamp) {
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
	ca := newTestCA(f, certOpts{})
	fake := &fakeTSA{t: f, ca: ca}
	imprint := sha256.Sum256(sig)
	f.Add(fake.token(imprint[:], big.NewInt(7)))
	f.Add([]byte{0x30, 0x03, 0x02, 0x01, 0x00})
	f.Fuzz(func(t *testing.T, token []byte) {
		for _, v := range []*TSAVerifier{recorded, ca.verifier} {
			if _, err := v.Verify(token, sig); err != nil && !errors.Is(err, ErrInvalidTimestamp) {
				t.Fatalf("error type: %v", err)
			}
		}
		if _, err := ParseResponse(token); err != nil && !errors.Is(err, ErrInvalidTimestamp) {
			t.Fatalf("error type: %v", err)
		}
	})
}
