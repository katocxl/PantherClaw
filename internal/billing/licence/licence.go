// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package licence encodes, signs and verifies PantherClaw licence documents
// (T-034, HR-063).
//
// A licence is a compact JWS (EdDSA, typ "pc-licence+jwt") over the claims,
// wrapped in a PEM block of type "PANTHERCLAW LICENCE". It is verified
// against the licence-signing root public keys embedded in this package
// (roots.json). The matching private keys are generated and kept offline by
// `pclaw-admin keygen --purpose licence`; CI and servers never hold them.
// Until the founder commits the offline public key, roots.json is empty and
// every licence is rejected, so servers run with Community limits.
package licence

import (
	"bytes"
	"crypto/ed25519"
	_ "embed"
	"encoding/json/v2"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/katocxl/pantherclaw/internal/billing/domain"
	"github.com/katocxl/pantherclaw/internal/platform/crypto/jws"
)

const (
	// PEMType is the PEM block type of a licence document.
	PEMType = "PANTHERCLAW LICENCE"
	// JOSEType is the JWS typ header of a licence.
	JOSEType = "pc-licence+jwt"
	// MaxDocumentBytes caps a licence file.
	MaxDocumentBytes = 16 << 10
	// KIDPrefix starts every licence root kid.
	KIDPrefix = "licence-root-"
)

//go:embed roots.json
var embeddedRoots []byte

// ErrInvalid is returned for every licence that fails verification. The
// wrapped detail is for operators; the effect is always the same.
var ErrInvalid = errors.New("licence: invalid licence")

// wireClaims is the JSON form of domain.Claims (JWT-style numeric dates).
type wireClaims struct {
	Version    int            `json:"v"`
	LicenceID  string         `json:"lid"`
	Licensee   string         `json:"sub"`
	CustomerID string         `json:"cid"`
	Edition    domain.Edition `json:"edition"`
	MaxAgents  int            `json:"max_agents"`
	MaxOrgs    int            `json:"max_orgs"`
	IssuedAt   int64          `json:"iat"`
	NotBefore  int64          `json:"nbf"`
	ExpiresAt  int64          `json:"exp"`
}

func toWire(c domain.Claims) wireClaims {
	return wireClaims{
		Version: c.Version, LicenceID: c.LicenceID, Licensee: c.Licensee, CustomerID: c.CustomerID,
		Edition: c.Edition, MaxAgents: c.MaxAgents, MaxOrgs: c.MaxOrgs,
		IssuedAt: c.IssuedAt.Unix(), NotBefore: c.NotBefore.Unix(), ExpiresAt: c.ExpiresAt.Unix(),
	}
}

func (w wireClaims) domain() domain.Claims {
	return domain.Claims{
		Version: w.Version, LicenceID: w.LicenceID, Licensee: w.Licensee, CustomerID: w.CustomerID,
		Edition: w.Edition, MaxAgents: w.MaxAgents, MaxOrgs: w.MaxOrgs,
		IssuedAt: time.Unix(w.IssuedAt, 0).UTC(), NotBefore: time.Unix(w.NotBefore, 0).UTC(), ExpiresAt: time.Unix(w.ExpiresAt, 0).UTC(),
	}
}

// Sign produces a licence document. It runs only in pclaw-admin, offline.
func Sign(c domain.Claims, signer *jws.Signer) ([]byte, error) {
	if err := c.Validate(); err != nil {
		return nil, err
	}
	if !strings.HasPrefix(signer.KeyID(), KIDPrefix) {
		return nil, fmt.Errorf("licence: signing key %q is not a licence root", signer.KeyID())
	}
	payload, err := json.Marshal(toWire(c))
	if err != nil {
		return nil, fmt.Errorf("licence: %w", err)
	}
	tok, err := signer.Sign(JOSEType, payload)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: PEMType, Bytes: []byte(tok)}), nil
}

// Roots are trusted licence-signing public keys by kid.
type Roots map[string]ed25519.PublicKey

// EmbeddedRoots returns the roots compiled into this binary.
func EmbeddedRoots() (Roots, error) { return ParseRoots(embeddedRoots) }

// ParseRoots parses a JWKS of Ed25519 public keys. Each kid must be the
// licence-root kid derived from its key, and private members are refused.
func ParseRoots(b []byte) (Roots, error) {
	var doc struct {
		Keys []jws.JWK `json:"keys"`
	}
	if err := json.Unmarshal(b, &doc, json.RejectUnknownMembers(true)); err != nil {
		return nil, fmt.Errorf("licence: roots: %w", err)
	}
	roots := Roots{}
	for _, k := range doc.Keys {
		pub, err := k.Key()
		if err != nil {
			return nil, fmt.Errorf("licence: roots: %w", err)
		}
		if k.Kid != RootKID(pub) {
			return nil, fmt.Errorf("licence: roots: kid %q does not match its key", k.Kid)
		}
		roots[k.Kid] = pub
	}
	return roots, nil
}

// RootKID derives the kid of a licence root public key.
func RootKID(pub ed25519.PublicKey) string { return KIDPrefix + jws.Thumbprint(pub)[:22] }

// Verify checks a licence document against roots and returns its claims.
// Dates are not checked here; domain.Evaluate applies them with grace rules.
func Verify(doc []byte, roots Roots) (domain.Claims, error) {
	if len(doc) == 0 || len(doc) > MaxDocumentBytes {
		return domain.Claims{}, fmt.Errorf("%w: document size", ErrInvalid)
	}
	block, rest := pem.Decode(doc)
	if block == nil || block.Type != PEMType || len(block.Headers) != 0 || len(bytes.TrimSpace(rest)) != 0 {
		return domain.Claims{}, fmt.Errorf("%w: not a single %s block", ErrInvalid, PEMType)
	}
	if len(roots) == 0 {
		return domain.Claims{}, fmt.Errorf("%w: no licence root keys are embedded in this build", ErrInvalid)
	}
	v, err := jws.NewVerifier(JOSEType, roots)
	if err != nil {
		return domain.Claims{}, fmt.Errorf("%w: %w", ErrInvalid, err)
	}
	payload, _, err := v.Verify(string(block.Bytes))
	if err != nil {
		return domain.Claims{}, fmt.Errorf("%w: signature: %w", ErrInvalid, err)
	}
	var w wireClaims
	if err := json.Unmarshal(payload, &w, json.RejectUnknownMembers(true)); err != nil {
		return domain.Claims{}, fmt.Errorf("%w: claims: %w", ErrInvalid, err)
	}
	c := w.domain()
	if err := c.Validate(); err != nil {
		return domain.Claims{}, fmt.Errorf("%w: %w", ErrInvalid, err)
	}
	return c, nil
}
