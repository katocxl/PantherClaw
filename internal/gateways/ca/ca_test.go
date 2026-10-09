// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package ca

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/keys"
)

func registry(t *testing.T, retiring ...keys.SigningKey) (*keys.Registry, keys.SigningKey) {
	t.Helper()
	reg := keys.NewRegistry()
	k, err := keys.GenerateSigningKey(keys.PurposeGatewayCA)
	if err != nil {
		t.Fatal(err)
	}
	if err := reg.Put(k); err != nil {
		t.Fatal(err)
	}
	for _, r := range retiring {
		r.State = keys.StateRetiring
		if err := reg.Put(r); err != nil {
			t.Fatal(err)
		}
	}
	return reg, k
}

func newCA(t *testing.T) *Authority {
	t.Helper()
	reg, _ := registry(t)
	a, err := New(reg)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func request(t *testing.T) (ed25519.PrivateKey, []byte) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "claims to be another gateway"},
		URIs:    []*url.URL{{Scheme: "pc", Opaque: "org/x/gateway/y/cert/z"}},
	}, priv)
	if err != nil {
		t.Fatal(err)
	}
	return priv, der
}

func identity() Identity {
	return Identity{Org: ids.New[ids.Org](), Gateway: ids.NewV7(), Cert: ids.NewV7()}
}

func verifyClient(t *testing.T, a *Authority, der []byte, at time.Time) (*x509.Certificate, error) {
	t.Helper()
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	_, err = cert.Verify(x509.VerifyOptions{Roots: a.Pool(), CurrentTime: at, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}})
	return cert, err
}

// TestHR180_ClientCertificatesAreShortLivedAndBindOneGateway: a gateway
// certificate lives at most 24 hours (plus the backdating for skew), is for
// client authentication only, and names exactly the org, gateway and
// certificate row the server chose; nothing from the request survives.
func TestHR180_ClientCertificatesAreShortLivedAndBindOneGateway(t *testing.T) {
	a := newCA(t)
	_, csr := request(t)
	pub, err := ParseRequest(csr)
	if err != nil {
		t.Fatal(err)
	}
	id, now := identity(), time.Now()
	iss, err := a.IssueClient(pub, id, now)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := verifyClient(t, a, iss.DER, now)
	if err != nil {
		t.Fatalf("issued certificate does not verify against the CA: %v", err)
	}
	if d := cert.NotAfter.Sub(cert.NotBefore); d > ClientLifetime+ClientSkew {
		t.Errorf("certificate lives %v", d)
	}
	if _, err := verifyClient(t, a, iss.DER, now.Add(ClientLifetime+time.Minute)); err == nil {
		t.Error("certificate still verifies after 24 hours")
	}
	if cert.IsCA || len(cert.ExtKeyUsage) != 1 || cert.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth {
		t.Errorf("usage: CA=%v ext=%v", cert.IsCA, cert.ExtKeyUsage)
	}
	if _, err := cert.Verify(x509.VerifyOptions{Roots: a.Pool(), CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err == nil {
		t.Error("a gateway certificate verifies as a server certificate")
	}
	got, err := ParseIdentity(cert)
	if err != nil || got != id {
		t.Fatalf("identity %+v %v, want %+v", got, err, id)
	}
	if strings.Contains(cert.Subject.CommonName, "another") {
		t.Error("the request's subject reached the certificate")
	}
}

// TestHR180_RequestsMustBeSignedByTheirEd25519Key: a request whose
// signature does not match its key, or for another key type, is refused
// (proof of possession).
func TestHR180_RequestsMustBeSignedByTheirEd25519Key(t *testing.T) {
	_, csr := request(t)
	tampered := bytes.Clone(csr)
	tampered[len(tampered)-1] ^= 1
	ec, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ecCSR, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, ec)
	if err != nil {
		t.Fatal(err)
	}
	for name, der := range map[string][]byte{"tampered": tampered, "ecdsa": ecCSR, "garbage": []byte("not a request"), "empty": nil} {
		if _, err := ParseRequest(der); !errors.Is(err, ErrRequest) {
			t.Errorf("%s: %v, want ErrRequest", name, err)
		}
	}
}

// TestHR180_TheCACertificateIsDeterministic: two server instances with the
// same key present the same CA certificate, so the enrollment pin holds.
func TestHR180_TheCACertificateIsDeterministic(t *testing.T) {
	reg, _ := registry(t)
	a1, err := New(reg)
	if err != nil {
		t.Fatal(err)
	}
	a2, err := New(reg)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a1.Certificate(), a2.Certificate()) || Fingerprint(a1.Certificate()) != Fingerprint(a2.Certificate()) {
		t.Fatal("CA certificate differs between instances")
	}
	if !strings.HasPrefix(Fingerprint(a1.Certificate()), "sha256:") || len(Fingerprint(a1.Certificate())) != 71 {
		t.Fatalf("fingerprint %q", Fingerprint(a1.Certificate()))
	}
	if _, err := New(keys.NewRegistry()); !errors.Is(err, ErrNoKey) {
		t.Fatalf("CA without a key: %v", err)
	}
}

// TestHR181_IdentityNeedsExactlyOneCanonicalURI: a certificate with another
// SAN, two URIs, another scheme or a non-canonical spelling names no
// gateway.
func TestHR181_IdentityNeedsExactlyOneCanonicalURI(t *testing.T) {
	a := newCA(t)
	id := identity()
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	canonical := id.URI()
	upper := &url.URL{Scheme: "pc", Opaque: strings.ToUpper(canonical.Opaque[:4]) + canonical.Opaque[4:]}
	other := &url.URL{Scheme: "spiffe", Host: "x", Path: "/" + canonical.Opaque}
	cases := map[string]*x509.Certificate{
		"extra DNS name": {URIs: []*url.URL{canonical}, DNSNames: []string{"gw.example.com"}},
		"two URIs":       {URIs: []*url.URL{canonical, canonical}},
		"no URI":         {},
		"other scheme":   {URIs: []*url.URL{other}},
		"upper case":     {URIs: []*url.URL{upper}},
		"extra segment":  {URIs: []*url.URL{{Scheme: "pc", Opaque: canonical.Opaque + "/x"}}},
	}
	for name, tmpl := range cases {
		tmpl.SerialNumber = a.serial()
		tmpl.NotBefore, tmpl.NotAfter = time.Now(), time.Now().Add(time.Hour)
		der, err := x509.CreateCertificate(nil, tmpl, a.cert, pub, a.key)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		cert, _ := x509.ParseCertificate(der)
		if _, err := ParseIdentity(cert); !errors.Is(err, ErrIdentity) {
			t.Errorf("%s: %v, want ErrIdentity", name, err)
		}
	}
}

// TestHR180_ARotationTrustsBothCAsAndIssuesWithTheNewOne: certificates from
// the retiring CA key keep verifying during the overlap; new certificates
// come only from the active key.
func TestHR180_ARotationTrustsBothCAsAndIssuesWithTheNewOne(t *testing.T) {
	oldReg, oldKey := registry(t)
	oldCA, err := New(oldReg)
	if err != nil {
		t.Fatal(err)
	}
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	before, err := oldCA.IssueClient(pub, identity(), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	reg, _ := registry(t, oldKey)
	a, err := New(reg)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(a.Certificate(), oldCA.Certificate()) {
		t.Fatal("the active CA is still the old one")
	}
	if _, err := verifyClient(t, a, before.DER, time.Now()); err != nil {
		t.Fatalf("a certificate from the retiring CA no longer verifies: %v", err)
	}
	after, _ := a.IssueClient(pub, identity(), time.Now())
	if _, err := verifyClient(t, oldCA, after.DER, time.Now()); err == nil {
		t.Fatal("a new certificate was issued by the retiring key")
	}
}

func TestServerCertificateNamesTheListener(t *testing.T) {
	a := newCA(t)
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	iss, err := a.IssueServer(pub, []string{"gw-api.example.com", "127.0.0.1"}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(iss.DER)
	for _, host := range []string{"gw-api.example.com", "127.0.0.1"} {
		if _, err := cert.Verify(x509.VerifyOptions{Roots: a.Pool(), DNSName: host}); err != nil {
			t.Errorf("%s: %v", host, err)
		}
	}
	if _, err := cert.Verify(x509.VerifyOptions{Roots: a.Pool(), DNSName: "evil.example.com"}); err == nil {
		t.Error("server certificate verifies for another name")
	}
}
