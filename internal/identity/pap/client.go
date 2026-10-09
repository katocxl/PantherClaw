// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pap

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json/v2"
	"errors"
	"time"

	"github.com/go-jose/go-jose/v4"
)

// ProofParams describe the request a workload signs a proof for.
type ProofParams struct {
	Method string
	URL    string
	Body   []byte
	// Token is the workload token sent with the request; empty for a
	// key-only proof.
	Token string
	Nonce string
	Now   time.Time
}

// NewProof signs a PAP-Proof for p with the workload key (the client side of
// PAP-1 §4). The jti is 128 random bits.
func NewProof(priv ed25519.PrivateKey, p ProofParams) (string, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return "", errors.New("pap: proof key must be an Ed25519 private key")
	}
	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		return "", err
	}
	bh := sha256.Sum256(p.Body)
	c := proofClaims{HTM: p.Method, HTU: p.URL, IAT: p.Now.Unix(), JTI: b64(id[:]), BH: b64(bh[:]), Nonce: p.Nonce}
	if p.Token != "" {
		ath := sha256.Sum256([]byte(p.Token))
		c.ATH = b64(ath[:])
	}
	payload, err := json.Marshal(c)
	if err != nil {
		return "", err
	}
	pub, _ := priv.Public().(ed25519.PublicKey)
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.EdDSA, Key: priv}, &jose.SignerOptions{
		EmbedJWK: false,
		ExtraHeaders: map[jose.HeaderKey]any{
			"typ": ProofType,
			"jwk": map[string]string{"kty": "OKP", "crv": "Ed25519", "x": b64(pub)},
		},
	})
	if err != nil {
		return "", err
	}
	obj, err := signer.Sign(payload)
	if err != nil {
		return "", err
	}
	return obj.CompactSerialize()
}
