// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package anchor implements the anchored global root of the evidence ledger
// (G0 M7 design decision 12, HR-195, PAP-1 §9.4): blinded per-org leaves,
// the global tree, the signed anchor statement, a Rekor v2 client that
// enters the statement as a hashedrekord v0.0.2 entry and verifies the
// log's inclusion proof and checkpoint, and an RFC 3161 client that
// timestamps the statement's signature and verifies the token.
//
// Everything is on the standard library (decision 3). HTTP goes through an
// injected Doer; the anchoring job wires the M1 egress client (HR-070..072)
// in a later slice. Nothing here is on the authorization path.
package anchor

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"fmt"
	"time"

	"github.com/katocxl/pantherclaw/internal/evidence/merkle"
)

const (
	// StatementType is the type of an anchor statement.
	StatementType = "pantherclaw.anchor"
	// MaxStatementBytes caps an encoded statement.
	MaxStatementBytes = 4 << 10
	// MaxOriginBytes caps the statement's origin.
	MaxOriginBytes = 256
	// maxSize keeps sizes exact in JSON numbers (RFC 8785 uses IEEE doubles).
	maxSize = 1 << 53
	// periodLayout is the statement's period: RFC 3339, UTC, seconds.
	periodLayout = "2006-01-02T15:04:05Z"
)

// ErrInvalidStatement reports a statement or signature that is malformed or
// does not verify.
var ErrInvalidStatement = errors.New("anchor: invalid anchor statement")

// Statement is what an anchor signs and enters in the transparency log: the
// global tree of one anchoring period. Its canonical form is RFC 8785 JSON
//
//	{"origin":…,"period":…,"root":…,"size":…,"type":"pantherclaw.anchor","v":1}
//
// with the period in RFC 3339 UTC seconds and the root in standard base64.
type Statement struct {
	Origin string      // the deployment's anchor origin
	Period time.Time   // start of the anchoring period
	Size   uint64      // leaves in the global tree (one per org)
	Root   merkle.Hash // root of the global tree
}

type statementJSON struct {
	V      int    `json:"v"`
	Type   string `json:"type"`
	Origin string `json:"origin"`
	Period string `json:"period"`
	Size   uint64 `json:"size"`
	Root   string `json:"root"`
}

func (s Statement) check() error {
	switch {
	case s.Origin == "" || len(s.Origin) > MaxOriginBytes:
		return fmt.Errorf("%w: origin must be 1..%d bytes", ErrInvalidStatement, MaxOriginBytes)
	case s.Size == 0 || s.Size > maxSize:
		return fmt.Errorf("%w: size must be 1..2^53", ErrInvalidStatement)
	case s.Period.IsZero():
		return fmt.Errorf("%w: missing period", ErrInvalidStatement)
	}
	return nil
}

// Canonical returns the statement's canonical JSON (RFC 8785).
func (s Statement) Canonical() ([]byte, error) {
	if err := s.check(); err != nil {
		return nil, err
	}
	b, err := json.Marshal(statementJSON{
		V: 1, Type: StatementType, Origin: s.Origin, Period: s.Period.UTC().Format(periodLayout),
		Size: s.Size, Root: base64.StdEncoding.EncodeToString(s.Root[:]),
	})
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidStatement, err)
	}
	v := jsontext.Value(b)
	if err := v.Canonicalize(); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidStatement, err)
	}
	return v, nil
}

// ParseStatement decodes a statement. It must be canonical JSON with
// exactly the statement's members.
func ParseStatement(b []byte) (Statement, error) {
	if len(b) > MaxStatementBytes {
		return Statement{}, fmt.Errorf("%w: larger than %d bytes", ErrInvalidStatement, MaxStatementBytes)
	}
	var w statementJSON
	if err := json.Unmarshal(b, &w, json.RejectUnknownMembers(true)); err != nil {
		return Statement{}, fmt.Errorf("%w: %w", ErrInvalidStatement, err)
	}
	if w.V != 1 || w.Type != StatementType {
		return Statement{}, fmt.Errorf("%w: unknown version or type", ErrInvalidStatement)
	}
	period, err := time.Parse(periodLayout, w.Period)
	if err != nil {
		return Statement{}, fmt.Errorf("%w: invalid period", ErrInvalidStatement)
	}
	raw, err := base64.StdEncoding.Strict().DecodeString(w.Root)
	if err != nil {
		return Statement{}, fmt.Errorf("%w: invalid root", ErrInvalidStatement)
	}
	root, err := merkle.HashFromBytes(raw)
	if err != nil {
		return Statement{}, fmt.Errorf("%w: invalid root", ErrInvalidStatement)
	}
	s := Statement{Origin: w.Origin, Period: period, Size: w.Size, Root: root}
	c, err := s.Canonical()
	if err != nil {
		return Statement{}, err
	}
	if !bytes.Equal(c, b) {
		return Statement{}, fmt.Errorf("%w: not in canonical form", ErrInvalidStatement)
	}
	return s, nil
}

// Signed is a signed anchor statement: the canonical statement, its SHA-256
// digest (what the hashedrekord entry records) and the anchors key's ECDSA
// P-256 SHA-256 signature in ASN.1 DER.
type Signed struct {
	Statement []byte
	Digest    [sha256.Size]byte
	Signature []byte
}

// SignStatement signs s with the anchors key, an ECDSA P-256 signer (the
// KeyProvider may hold the private key).
func SignStatement(key crypto.Signer, s Statement) (Signed, error) {
	pub, ok := key.Public().(*ecdsa.PublicKey)
	if !ok || pub.Curve != elliptic.P256() {
		return Signed{}, errors.New("anchor: the anchors key must be ECDSA P-256")
	}
	c, err := s.Canonical()
	if err != nil {
		return Signed{}, err
	}
	d := sha256.Sum256(c)
	sig, err := key.Sign(rand.Reader, d[:], crypto.SHA256)
	if err != nil {
		return Signed{}, fmt.Errorf("anchor: sign statement: %w", err)
	}
	if !ecdsa.VerifyASN1(pub, d[:], sig) {
		return Signed{}, errors.New("anchor: the anchors key produced an invalid signature")
	}
	return Signed{Statement: c, Digest: d, Signature: sig}, nil
}

// VerifyStatement checks a statement's signature against the anchors
// public key (PKIX DER, ECDSA P-256) and parses it.
func VerifyStatement(publicKey, statement, signature []byte) (Statement, error) {
	pub, err := ParseAnchorKey(publicKey)
	if err != nil {
		return Statement{}, err
	}
	s, err := ParseStatement(statement)
	if err != nil {
		return Statement{}, err
	}
	d := sha256.Sum256(statement)
	if !ecdsa.VerifyASN1(pub, d[:], signature) {
		return Statement{}, fmt.Errorf("%w: signature does not verify", ErrInvalidStatement)
	}
	return s, nil
}

// ParseAnchorKey parses an anchors public key: PKIX DER of an ECDSA P-256
// key.
func ParseAnchorKey(der []byte) (*ecdsa.PublicKey, error) {
	k, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, fmt.Errorf("%w: anchors key: %w", ErrInvalidStatement, err)
	}
	pub, ok := k.(*ecdsa.PublicKey)
	if !ok || pub.Curve != elliptic.P256() {
		return nil, fmt.Errorf("%w: the anchors key must be ECDSA P-256", ErrInvalidStatement)
	}
	return pub, nil
}
