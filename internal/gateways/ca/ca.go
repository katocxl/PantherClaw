// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package ca is PantherClaw's internal certificate authority for gateway
// mTLS (G0 M6, HR-180, HR-181). It issues 24-hour Ed25519 client
// certificates that bind exactly one gateway and org in a URI SAN, and the
// gateway listener's own server certificate. The CA certificate is derived
// deterministically from the gateway_ca signing key (a fixed template and a
// deterministic Ed25519 signature), so every server instance presents the
// same certificate and the SHA-256 pin given to enrolling gateways stays
// valid for the key's lifetime. Nothing a gateway puts in its certificate
// request is trusted except its public key and its signature.
package ca

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/katocxl/pantherclaw/internal/platform/crypto/jws"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/keys"
)

// Lifetimes (G0 M6 design decisions 1 and 2).
const (
	// ClientLifetime is a gateway certificate's validity after its start.
	ClientLifetime = 24 * time.Hour
	// ClientSkew backdates a certificate's start for clock differences.
	ClientSkew = 5 * time.Minute
	// ServerLifetime is the gateway listener certificate's validity.
	ServerLifetime = 7 * 24 * time.Hour
	// caLifetime is the CA certificate's validity from its fixed start; the
	// CA is replaced by rotating its key long before.
	caLifetime = 10 * 365 * 24 * time.Hour
)

// caEpoch is the fixed start of every CA certificate (determinism).
var caEpoch = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

// Errors.
var (
	// ErrRequest reports a certificate request that is malformed, not
	// signed by its key, or not for an Ed25519 key.
	ErrRequest = errors.New("ca: invalid certificate request")
	// ErrIdentity reports a certificate without exactly one valid gateway
	// identity.
	ErrIdentity = errors.New("ca: certificate does not name exactly one gateway")
	// ErrNoKey reports a registry without an active gateway_ca key.
	ErrNoKey = errors.New("ca: no active gateway CA key")
)

// Identity is what a gateway certificate binds: one org, one gateway, one
// certificate row.
type Identity struct {
	Org     ids.OrgID
	Gateway ids.UUID
	Cert    ids.UUID
}

const uriScheme = "pc"

// URI is the identity's URI SAN: pc:org/<org>/gateway/<gateway>/cert/<cert>.
func (i Identity) URI() *url.URL {
	return &url.URL{Scheme: uriScheme, Opaque: "org/" + i.Org.String() + "/gateway/" + i.Gateway.String() + "/cert/" + i.Cert.String()}
}

// ParseIdentity reads the identity of a verified client certificate. It
// requires exactly one URI SAN, of the gateway form, and no other SAN.
func ParseIdentity(cert *x509.Certificate) (Identity, error) {
	if len(cert.URIs) != 1 || len(cert.DNSNames)+len(cert.EmailAddresses)+len(cert.IPAddresses) != 0 {
		return Identity{}, ErrIdentity
	}
	u := cert.URIs[0]
	if u.Scheme != uriScheme || u.Host != "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return Identity{}, ErrIdentity
	}
	parts := strings.Split(u.Opaque, "/")
	if len(parts) != 6 || parts[0] != "org" || parts[2] != "gateway" || parts[4] != "cert" {
		return Identity{}, ErrIdentity
	}
	org, err1 := ids.Parse[ids.Org](parts[1])
	gw, err2 := ids.ParseUUID(parts[3])
	c, err3 := ids.ParseUUID(parts[5])
	if err1 != nil || err2 != nil || err3 != nil || org.IsZero() || gw.IsZero() || c.IsZero() {
		return Identity{}, ErrIdentity
	}
	// The canonical form must round-trip: no case or encoding variants.
	if u.Opaque != (Identity{Org: org, Gateway: gw, Cert: c}).URI().Opaque {
		return Identity{}, ErrIdentity
	}
	return Identity{Org: org, Gateway: gw, Cert: c}, nil
}

// Authority holds the active CA key and the certificates of every
// non-revoked CA key (a rotation trusts old and new).
type Authority struct {
	key    ed25519.PrivateKey
	cert   *x509.Certificate
	der    []byte
	trust  []*x509.Certificate
	random func(b []byte)
}

// New builds the CA from the registry's gateway_ca keys: the active key
// issues; retiring keys (loaded with their private half for this purpose
// only, so that their certificates can be derived again) are still trusted
// during a rotation but never issue.
func New(reg *keys.Registry) (*Authority, error) {
	ks := reg.Keys(keys.PurposeGatewayCA)
	if len(ks) == 0 || ks[0].State != keys.StateActive {
		return nil, ErrNoKey
	}
	a := &Authority{key: ks[0].Private.Reveal(), random: func(b []byte) { _, _ = rand.Read(b) }}
	for i, k := range ks {
		if len(k.Private.Reveal()) != ed25519.PrivateKeySize {
			continue // a retiring key without its private half cannot be derived: not trusted
		}
		der, cert, err := caCertificate(k)
		if err != nil {
			return nil, err
		}
		if i == 0 {
			a.cert, a.der = cert, der
		}
		a.trust = append(a.trust, cert)
	}
	return a, nil
}

// caCertificate derives the self-signed CA certificate of a key.
func caCertificate(k keys.SigningKey) ([]byte, *x509.Certificate, error) {
	tmpl := caTemplate(k)
	priv := k.Private.Reveal()
	der, err := x509.CreateCertificate(nil, tmpl, tmpl, priv.Public(), priv)
	if err != nil {
		return nil, nil, fmt.Errorf("ca: create CA certificate: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, fmt.Errorf("ca: parse CA certificate: %w", err)
	}
	return der, cert, nil
}

// caTemplate is the fixed CA template of a key: everything in it derives
// from the public key, so the signed certificate is the same everywhere.
func caTemplate(k keys.SigningKey) *x509.Certificate {
	sum := sha256.Sum256(k.Public)
	serial := new(big.Int).SetBytes(sum[:16])
	return &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "PantherClaw gateway CA " + k.KID},
		NotBefore:             caEpoch,
		NotAfter:              caEpoch.Add(caLifetime),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
		SubjectKeyId:          sum[:20],
	}
}

// Certificate returns the active CA certificate (DER).
func (a *Authority) Certificate() []byte { return append([]byte(nil), a.der...) }

// Fingerprint is the "sha256:<hex>" pin of a DER certificate.
func Fingerprint(der []byte) string {
	sum := sha256.Sum256(der)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// Pool returns the CA certificates a TLS server trusts for client
// certificates: the active CA and, during a rotation, the retiring ones.
func (a *Authority) Pool() *x509.CertPool {
	p := x509.NewCertPool()
	for _, c := range a.trust {
		p.AddCert(c)
	}
	return p
}

// Issued is a certificate the CA issued.
type Issued struct {
	DER        []byte
	Serial     []byte
	Thumbprint string // RFC 7638 thumbprint of the certificate's key
	NotBefore  time.Time
	NotAfter   time.Time
}

// ParseRequest checks a DER PKCS #10 request: it must parse, be for an
// Ed25519 key and be signed by that key (proof of possession, HR-180). It
// returns the key; nothing else in the request is used.
func ParseRequest(der []byte) (ed25519.PublicKey, error) {
	if len(der) == 0 || len(der) > 4096 {
		return nil, ErrRequest
	}
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrRequest, err)
	}
	if csr.SignatureAlgorithm != x509.PureEd25519 {
		return nil, fmt.Errorf("%w: signature algorithm %v", ErrRequest, csr.SignatureAlgorithm)
	}
	pub, ok := csr.PublicKey.(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("%w: not an Ed25519 key", ErrRequest)
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrRequest, err)
	}
	return pub, nil
}

// IssueClient issues a gateway client certificate for pub, valid from now
// minus ClientSkew until now plus ClientLifetime.
func (a *Authority) IssueClient(pub ed25519.PublicKey, id Identity, now time.Time) (Issued, error) {
	if len(pub) != ed25519.PublicKeySize || id.Org.IsZero() || id.Gateway.IsZero() || id.Cert.IsZero() {
		return Issued{}, ErrRequest
	}
	tmpl := &x509.Certificate{
		SerialNumber:          a.serial(),
		Subject:               pkix.Name{CommonName: "gateway " + id.Gateway.String()},
		URIs:                  []*url.URL{id.URI()},
		NotBefore:             now.Add(-ClientSkew),
		NotAfter:              now.Add(ClientLifetime),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}
	return a.issue(tmpl, pub)
}

// IssueServer issues the gateway listener's server certificate for pub and
// the given names (DNS names or IP addresses).
func (a *Authority) IssueServer(pub ed25519.PublicKey, names []string, now time.Time) (Issued, error) {
	if len(pub) != ed25519.PublicKeySize || len(names) == 0 {
		return Issued{}, errors.New("ca: a server certificate needs a key and at least one name")
	}
	tmpl := &x509.Certificate{
		SerialNumber:          a.serial(),
		Subject:               pkix.Name{CommonName: "pantherclaw-server gateway listener"},
		NotBefore:             now.Add(-ClientSkew),
		NotAfter:              now.Add(ServerLifetime),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	for _, n := range names {
		if ip := net.ParseIP(n); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		} else {
			tmpl.DNSNames = append(tmpl.DNSNames, n)
		}
	}
	return a.issue(tmpl, pub)
}

func (a *Authority) issue(tmpl *x509.Certificate, pub ed25519.PublicKey) (Issued, error) {
	der, err := x509.CreateCertificate(nil, tmpl, a.cert, pub, a.key)
	if err != nil {
		return Issued{}, fmt.Errorf("ca: issue: %w", err)
	}
	return Issued{
		DER: der, Serial: tmpl.SerialNumber.Bytes(), Thumbprint: jws.Thumbprint(pub),
		NotBefore: tmpl.NotBefore.UTC().Truncate(time.Second), NotAfter: tmpl.NotAfter.UTC().Truncate(time.Second),
	}, nil
}

// serial is a random positive 128-bit serial number.
func (a *Authority) serial() *big.Int {
	b := make([]byte, 16)
	a.random(b)
	b[0] &= 0x7f
	if b[0] == 0 {
		b[0] = 1
	}
	return new(big.Int).SetBytes(b)
}
