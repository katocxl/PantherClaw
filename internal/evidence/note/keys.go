// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package note

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
)

// Signature type identifiers (c2sp.org/signed-note).
const (
	// TypeEd25519 is the Ed25519 signature type.
	TypeEd25519 = 0x01
	// TypeECDSA is the ECDSA signature type.
	TypeECDSA = 0x02
	// TypeUnregistered precedes the name of a type without an assigned byte.
	TypeUnregistered = 0xff
)

// MLDSA65TypeName names PantherClaw's ML-DSA-65 note signatures (FIPS 204,
// pure ML-DSA-65 over the note text with the context MLDSA65Context). The
// type has no assigned byte, so its identifier in the key ID is 0xff
// followed by this name:
//
//	key ID = SHA-256(key name ‖ 0x0A ‖ 0xff ‖ "pantherclaw.ml-dsa-65.v1" ‖ 1,952-byte public key)[:4]
//
// The signature is the 3,309-byte ML-DSA-65 signature. PAP-1 §9.4 names it.
const MLDSA65TypeName = "pantherclaw.ml-dsa-65.v1"

// MLDSA65Context is the FIPS 204 context string of ML-DSA-65 note
// signatures. It keeps them apart from anything else the same key signs
// (the checkpoints_pq key also co-signs evidence-pack manifests).
const MLDSA65Context = "pantherclaw.signed-note.v1"

// MLDSA65KeyName returns the key name of the ML-DSA-65 co-signature on a
// checkpoint of origin: a name of its own, so verifiers that only know the
// Ed25519 key ignore the line.
func MLDSA65KeyName(origin string) string { return origin + "/ml-dsa-65" }

type signer struct {
	name string
	id   uint32
	sign func([]byte) ([]byte, error)
}

func (s *signer) Name() string                    { return s.name }
func (s *signer) KeyID() uint32                   { return s.id }
func (s *signer) Sign(msg []byte) ([]byte, error) { return s.sign(msg) }

type verifier struct {
	name   string
	id     uint32
	verify func(msg, sig []byte) bool
}

func (v *verifier) Name() string                { return v.name }
func (v *verifier) KeyID() uint32               { return v.id }
func (v *verifier) Verify(msg, sig []byte) bool { return v.verify(msg, sig) }

func checkName(name string) error {
	if !ValidKeyName(name) {
		return fmt.Errorf("%w: invalid key name %q", ErrMalformed, name)
	}
	return nil
}

// Ed25519KeyID returns the key ID of an Ed25519 key named name.
func Ed25519KeyID(name string, pub ed25519.PublicKey) uint32 {
	return KeyID(name, []byte{TypeEd25519}, pub)
}

// NewEd25519Signer returns a signer for an Ed25519 key.
func NewEd25519Signer(name string, priv ed25519.PrivateKey) (Signer, error) {
	if err := checkName(name); err != nil {
		return nil, err
	}
	if len(priv) != ed25519.PrivateKeySize {
		return nil, errors.New("note: invalid Ed25519 private key")
	}
	pub, _ := priv.Public().(ed25519.PublicKey)
	return &signer{name: name, id: Ed25519KeyID(name, pub), sign: func(msg []byte) ([]byte, error) {
		return ed25519.Sign(priv, msg), nil
	}}, nil
}

// NewEd25519Verifier returns a verifier for an Ed25519 key.
func NewEd25519Verifier(name string, pub ed25519.PublicKey) (Verifier, error) {
	if err := checkName(name); err != nil {
		return nil, err
	}
	if len(pub) != ed25519.PublicKeySize {
		return nil, errors.New("note: invalid Ed25519 public key")
	}
	pub = append(ed25519.PublicKey(nil), pub...)
	return &verifier{name: name, id: Ed25519KeyID(name, pub), verify: func(msg, sig []byte) bool {
		return len(sig) == ed25519.SignatureSize && ed25519.Verify(pub, msg, sig)
	}}, nil
}

// ECDSAKeyID returns the key ID of an ECDSA key as Rekor v2 and the
// transparency-dev witness compute it: the first four bytes of
// SHA-256(PKIX DER of the public key). Unlike other types it binds neither
// the key name nor the type byte.
func ECDSAKeyID(pub *ecdsa.PublicKey) (uint32, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return 0, fmt.Errorf("note: ECDSA public key: %w", err)
	}
	sum := sha256.Sum256(der)
	return binary.BigEndian.Uint32(sum[:]), nil
}

// NewECDSAVerifier returns a verifier for an ECDSA P-256 key. The signature
// is ASN.1 DER over SHA-256 of the note text.
func NewECDSAVerifier(name string, pub *ecdsa.PublicKey) (Verifier, error) {
	if err := checkName(name); err != nil {
		return nil, err
	}
	if pub == nil || pub.Curve != elliptic.P256() {
		return nil, errors.New("note: only ECDSA P-256 keys are supported")
	}
	id, err := ECDSAKeyID(pub)
	if err != nil {
		return nil, err
	}
	return &verifier{name: name, id: id, verify: func(msg, sig []byte) bool {
		d := sha256.Sum256(msg)
		return ecdsa.VerifyASN1(pub, d[:], sig)
	}}, nil
}

// NewECDSASigner returns a signer for an ECDSA P-256 key (test logs).
func NewECDSASigner(name string, priv *ecdsa.PrivateKey) (Signer, error) {
	if err := checkName(name); err != nil {
		return nil, err
	}
	if priv == nil || priv.Curve != elliptic.P256() {
		return nil, errors.New("note: only ECDSA P-256 keys are supported")
	}
	id, err := ECDSAKeyID(&priv.PublicKey)
	if err != nil {
		return nil, err
	}
	return &signer{name: name, id: id, sign: func(msg []byte) ([]byte, error) {
		d := sha256.Sum256(msg)
		return ecdsa.SignASN1(rand.Reader, priv, d[:])
	}}, nil
}

// NewPKIXVerifier returns a verifier for a log key given as PKIX DER
// (SubjectPublicKeyInfo), as Sigstore's trusted_root.json carries it:
// Ed25519 or ECDSA P-256.
func NewPKIXVerifier(name string, der []byte) (Verifier, error) {
	k, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, fmt.Errorf("note: log public key: %w", err)
	}
	switch k := k.(type) {
	case ed25519.PublicKey:
		return NewEd25519Verifier(name, k)
	case *ecdsa.PublicKey:
		return NewECDSAVerifier(name, k)
	default:
		return nil, fmt.Errorf("note: log key type %T is not supported", k)
	}
}

func mldsa65Type() []byte { return append([]byte{TypeUnregistered}, MLDSA65TypeName...) }

// MLDSA65KeyID returns the key ID of an ML-DSA-65 key named name.
func MLDSA65KeyID(name string, pub *mldsa.PublicKey) uint32 {
	return KeyID(name, mldsa65Type(), pub.Bytes())
}

// NewMLDSA65Signer returns a signer for an ML-DSA-65 key.
func NewMLDSA65Signer(name string, priv *mldsa.PrivateKey) (Signer, error) {
	if err := checkName(name); err != nil {
		return nil, err
	}
	if priv == nil || priv.PublicKey().Parameters() != mldsa.MLDSA65() {
		return nil, errors.New("note: not an ML-DSA-65 private key")
	}
	opts := &mldsa.Options{Context: MLDSA65Context}
	return &signer{name: name, id: MLDSA65KeyID(name, priv.PublicKey()), sign: func(msg []byte) ([]byte, error) {
		return priv.Sign(nil, msg, opts)
	}}, nil
}

// NewMLDSA65Verifier returns a verifier for an ML-DSA-65 key.
func NewMLDSA65Verifier(name string, pub *mldsa.PublicKey) (Verifier, error) {
	if err := checkName(name); err != nil {
		return nil, err
	}
	if pub == nil || pub.Parameters() != mldsa.MLDSA65() {
		return nil, errors.New("note: not an ML-DSA-65 public key")
	}
	opts := &mldsa.Options{Context: MLDSA65Context}
	return &verifier{name: name, id: MLDSA65KeyID(name, pub), verify: func(msg, sig []byte) bool {
		return len(sig) == mldsa.MLDSA65SignatureSize && mldsa.Verify(pub, msg, sig, opts) == nil
	}}, nil
}
