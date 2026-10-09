// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package control is the gateway's side of its relationship with the
// server (G0 M6): its identity (an Ed25519 key and a 24-hour client
// certificate from PantherClaw's internal CA, HR-180), enrollment with a
// single-use token, renewal before expiry, and the mutual-TLS client every
// control-plane call uses (HR-181). The gateway's certificate is presented
// only on this client; egress transports never carry it (HR-074).
package control

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/katocxl/pantherclaw/internal/gateways/ca"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// identityFile is the identity's file name inside the identity directory.
const identityFile = "identity.json"

// RenewAfter is when a certificate is renewed: two thirds of its 24 hours.
const RenewAfter = 16 * time.Hour

// Errors.
var (
	// ErrNoIdentity reports an identity directory without an identity.
	ErrNoIdentity = errors.New("control: no gateway identity; enroll first")
	// ErrPin reports a CA certificate whose SHA-256 is not the pin.
	ErrPin = errors.New("control: the CA certificate does not match the pinned SHA-256")
	// ErrIdentity reports a malformed or inconsistent identity.
	ErrIdentity = errors.New("control: invalid gateway identity")
)

// Identity is the gateway's identity: who it is, its key and certificate,
// and the CA it trusts for the server's gateway listener.
type Identity struct {
	Org           ids.OrgID
	Gateway       ids.UUID
	Cert          ids.UUID
	GatewayAPIURL string
	CASHA256      string

	key      ed25519.PrivateKey
	certDER  []byte
	caDER    []byte
	leaf     *x509.Certificate
	caCert   *x509.Certificate
	notAfter time.Time
}

// stored is the identity file (0600).
type stored struct {
	V             int    `json:"v"`
	GatewayAPIURL string `json:"gateway_api_url"`
	CASHA256      string `json:"ca_sha256"`
	Key           string `json:"key"`         // base64url Ed25519 seed
	Certificate   string `json:"certificate"` // base64 DER
	CA            string `json:"ca"`          // base64 DER
}

// Pin returns the "sha256:<hex>" pin of a DER certificate.
func Pin(der []byte) string {
	sum := sha256.Sum256(der)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// newIdentity checks that cert is for key, chains to caDER, and names one
// gateway; that caDER matches pin.
func newIdentity(key ed25519.PrivateKey, certDER, caDER []byte, pin, gatewayAPIURL string) (*Identity, error) {
	if Pin(caDER) != pin {
		return nil, ErrPin
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil || !caCert.IsCA {
		return nil, fmt.Errorf("%w: CA certificate", ErrIdentity)
	}
	leaf, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("%w: certificate: %w", ErrIdentity, err)
	}
	pub, ok := leaf.PublicKey.(ed25519.PublicKey)
	if !ok || !pub.Equal(key.Public()) {
		return nil, fmt.Errorf("%w: the certificate is not for this key", ErrIdentity)
	}
	pool := x509.NewCertPool()
	pool.AddCert(caCert)
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots: pool, CurrentTime: leaf.NotBefore.Add(time.Minute),
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}); err != nil {
		return nil, fmt.Errorf("%w: the certificate does not chain to the pinned CA: %w", ErrIdentity, err)
	}
	gw, err := ca.ParseIdentity(leaf)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrIdentity, err)
	}
	return &Identity{
		Org: gw.Org, Gateway: gw.Gateway, Cert: gw.Cert, GatewayAPIURL: gatewayAPIURL, CASHA256: pin,
		key: key, certDER: certDER, caDER: caDER, leaf: leaf, caCert: caCert, notAfter: leaf.NotAfter,
	}, nil
}

// TLSCertificate is the client certificate for the mTLS client.
func (i *Identity) TLSCertificate() tls.Certificate {
	return tls.Certificate{Certificate: [][]byte{i.certDER}, PrivateKey: i.key, Leaf: i.leaf}
}

// Roots trusts only the internal CA, for the server's gateway listener.
func (i *Identity) Roots() *x509.CertPool {
	p := x509.NewCertPool()
	p.AddCert(i.caCert)
	return p
}

// NotBefore and NotAfter bound the certificate.
func (i *Identity) NotBefore() time.Time { return i.leaf.NotBefore }

// NotAfter is when the certificate expires.
func (i *Identity) NotAfter() time.Time { return i.notAfter }

// Expired reports whether the certificate is unusable at now.
func (i *Identity) Expired(now time.Time) bool { return !now.Before(i.notAfter) }

// Load reads the identity from dir and checks it against pin (when pin is
// empty, the pin stored with the identity is used).
func Load(dir, pin string) (*Identity, error) {
	b, err := os.ReadFile(filepath.Join(dir, identityFile)) //nolint:gosec // G304: operator-chosen identity directory
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrNoIdentity
	} else if err != nil {
		return nil, err
	}
	var s stored
	if err := json.Unmarshal(b, &s, json.RejectUnknownMembers(true)); err != nil || s.V != 1 {
		return nil, fmt.Errorf("%w: %s", ErrIdentity, identityFile)
	}
	if pin == "" {
		pin = s.CASHA256
	} else if pin != s.CASHA256 {
		return nil, ErrPin
	}
	seed, err1 := base64.RawURLEncoding.DecodeString(s.Key)
	cert, err2 := base64.StdEncoding.DecodeString(s.Certificate)
	caDER, err3 := base64.StdEncoding.DecodeString(s.CA)
	if err1 != nil || err2 != nil || err3 != nil || len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("%w: %s", ErrIdentity, identityFile)
	}
	return newIdentity(ed25519.NewKeyFromSeed(seed), cert, caDER, pin, s.GatewayAPIURL)
}

// Save writes the identity to dir (0700) as a 0600 file, replacing the
// previous one atomically.
func (i *Identity) Save(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	b, err := json.Marshal(stored{
		V: 1, GatewayAPIURL: i.GatewayAPIURL, CASHA256: i.CASHA256,
		Key: base64.RawURLEncoding.EncodeToString(i.key.Seed()), Certificate: base64.StdEncoding.EncodeToString(i.certDER),
		CA: base64.StdEncoding.EncodeToString(i.caDER),
	})
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, identityFile+".*")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(b); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), filepath.Join(dir, identityFile))
}
