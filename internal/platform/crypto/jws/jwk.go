// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package jws

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"errors"
)

// JWK is the public JSON Web Key form of an Ed25519 key (RFC 8037).
type JWK struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Kid string `json:"kid,omitempty"`
	Alg string `json:"alg,omitempty"`
	Use string `json:"use,omitempty"`
}

// PublicJWK returns the JWK for pub with the given kid.
func PublicJWK(pub ed25519.PublicKey, kid string) JWK {
	return JWK{Kty: "OKP", Crv: "Ed25519", X: base64.RawURLEncoding.EncodeToString(pub), Kid: kid, Alg: "EdDSA", Use: "sig"}
}

// Key returns the Ed25519 public key in j, rejecting anything else.
func (j JWK) Key() (ed25519.PublicKey, error) {
	if j.Kty != "OKP" || j.Crv != "Ed25519" || (j.Alg != "" && j.Alg != "EdDSA") {
		return nil, errors.New("jws: JWK is not an Ed25519 signing key")
	}
	b, err := base64.RawURLEncoding.Strict().DecodeString(j.X)
	if err != nil || len(b) != ed25519.PublicKeySize {
		return nil, errors.New("jws: JWK has an invalid Ed25519 public key")
	}
	return ed25519.PublicKey(b), nil
}

// Thumbprint returns the RFC 7638 SHA-256 JWK thumbprint of an Ed25519 public
// key, base64url-encoded (PAP/1 jkt). The required members are serialized in
// lexicographic order with no whitespace: {"crv","kty","x"}.
func Thumbprint(pub ed25519.PublicKey) string {
	canonical := `{"crv":"Ed25519","kty":"OKP","x":"` + base64.RawURLEncoding.EncodeToString(pub) + `"}`
	sum := sha256.Sum256([]byte(canonical))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}
