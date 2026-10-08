// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package keys

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json/v2"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"

	"github.com/katocxl/pantherclaw/internal/platform/crypto/jws"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
)

// Purpose separates signing keys: a key signs for exactly one purpose, so a
// compromise or misuse of one purpose's key does not forge another's tokens
// (SB-1 least privilege).
type Purpose string

// Signing purposes.
const (
	PurposeReceipts       Purpose = "receipts"        // decision/execution/effect receipts
	PurposePermits        Purpose = "permits"         // dispatch permits
	PurposeWorkloadTokens Purpose = "workload_tokens" // PAP/1 workload tokens
	PurposeCheckpoints    Purpose = "checkpoints"     // ledger checkpoints
	PurposeAccessTokens   Purpose = "access_tokens"   // control-plane access tokens (ADR-0016); never published
)

// Purposes lists every signing purpose.
func Purposes() []Purpose {
	return []Purpose{PurposeReceipts, PurposePermits, PurposeWorkloadTokens, PurposeCheckpoints, PurposeAccessTokens}
}

// Valid reports whether p is a known purpose.
func (p Purpose) Valid() bool { return slices.Contains(Purposes(), p) }

// State is the lifecycle state of a signing key.
type State string

// Key states. Active keys sign; Retiring keys only verify (rotation overlap);
// Revoked keys do neither and are not published.
const (
	StateActive   State = "ACTIVE"
	StateRetiring State = "RETIRING"
	StateRevoked  State = "REVOKED"
)

// SigningKey is an Ed25519 key for one purpose. Private is unset for keys
// that only verify.
type SigningKey struct {
	KID     string
	Purpose Purpose
	State   State
	Public  ed25519.PublicKey
	Private pclog.Secret[ed25519.PrivateKey]
}

// GenerateSigningKey creates a new active key for purpose. The kid is
// "<purpose>-<RFC 7638 thumbprint prefix>".
func GenerateSigningKey(purpose Purpose) (SigningKey, error) {
	if !purpose.Valid() {
		return SigningKey{}, fmt.Errorf("keys: unknown purpose %q", purpose)
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return SigningKey{}, fmt.Errorf("keys: generate: %w", err)
	}
	return SigningKey{
		KID:     KIDFor(purpose, pub),
		Purpose: purpose,
		State:   StateActive,
		Public:  pub,
		Private: pclog.NewSecret(priv),
	}, nil
}

// KIDFor derives the kid of a public key for a purpose.
func KIDFor(purpose Purpose, pub ed25519.PublicKey) string {
	return strings.ReplaceAll(string(purpose), "_", "-") + "-" + jws.Thumbprint(pub)[:22]
}

// Registry holds the signing keys in memory. It is safe for concurrent use.
type Registry struct {
	mu   sync.RWMutex
	keys map[string]SigningKey
}

// NewRegistry returns an empty Registry.
func NewRegistry() *Registry { return &Registry{keys: map[string]SigningKey{}} }

// Put adds or replaces a key. At most one key per purpose may be Active, and
// an Active key must carry its private half.
func (r *Registry) Put(k SigningKey) error {
	if !k.Purpose.Valid() {
		return fmt.Errorf("keys: unknown purpose %q", k.Purpose)
	}
	if len(k.Public) != ed25519.PublicKeySize || k.KID != KIDFor(k.Purpose, k.Public) {
		return fmt.Errorf("keys: kid %q does not match its public key and purpose", k.KID)
	}
	switch k.State {
	case StateActive:
		priv := k.Private.Reveal()
		if len(priv) != ed25519.PrivateKeySize || !priv.Public().(ed25519.PublicKey).Equal(k.Public) {
			return fmt.Errorf("keys: active key %q needs its matching private key", k.KID)
		}
	case StateRetiring, StateRevoked:
	default:
		return fmt.Errorf("keys: invalid state %q", k.State)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if k.State == StateActive {
		for kid, other := range r.keys {
			if kid != k.KID && other.Purpose == k.Purpose && other.State == StateActive {
				return fmt.Errorf("keys: purpose %q already has active key %q", k.Purpose, kid)
			}
		}
	}
	r.keys[k.KID] = k
	return nil
}

// ErrNoActiveKey reports a purpose without an active signing key.
var ErrNoActiveKey = errors.New("keys: no active signing key")

// Signer returns a signer with the active key of purpose.
func (r *Registry) Signer(purpose Purpose) (*jws.Signer, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, k := range r.keys {
		if k.Purpose == purpose && k.State == StateActive {
			return jws.NewSigner(k.KID, k.Private.Reveal())
		}
	}
	return nil, fmt.Errorf("%w for %q", ErrNoActiveKey, purpose)
}

// Verifier returns a verifier that accepts tokens of type typ signed by any
// non-revoked key of purpose, and by no other key.
func (r *Registry) Verifier(purpose Purpose, typ string) (*jws.Verifier, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	pubs := map[string]ed25519.PublicKey{}
	for kid, k := range r.keys {
		if k.Purpose == purpose && k.State != StateRevoked {
			pubs[kid] = k.Public
		}
	}
	return jws.NewVerifier(typ, pubs)
}

// published lists the purposes whose public keys appear in the JWKS
// (PAP-1 §11). Checkpoint keys are verified through `pclaw verify` bundles.
var published = []Purpose{PurposeReceipts, PurposePermits, PurposeWorkloadTokens}

// JWKS returns the public JWKS document for /.well-known/pantherclaw/jwks.json:
// active and retiring keys of published purposes, sorted by kid.
func (r *Registry) JWKS() ([]byte, error) {
	r.mu.RLock()
	var set []jws.JWK
	for kid, k := range r.keys {
		if k.State != StateRevoked && slices.Contains(published, k.Purpose) {
			set = append(set, jws.PublicJWK(k.Public, kid))
		}
	}
	r.mu.RUnlock()
	slices.SortFunc(set, func(a, b jws.JWK) int { return strings.Compare(a.Kid, b.Kid) })
	if set == nil {
		set = []jws.JWK{}
	}
	return json.Marshal(struct {
		Keys []jws.JWK `json:"keys"`
	}{Keys: set})
}
