// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package payments

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/katocxl/pantherclaw/internal/platform/crypto/jws"
	"github.com/katocxl/pantherclaw/internal/platform/keys"
)

// HeaderAction carries the action token (PAP-1 §10).
const HeaderAction = "PAP-Action"

// Action tokens (G0 M6 design decision 17, PAP-1 §10, HR-188). A
// target-enforced connection's dispatches carry a JWS that PantherClaw
// minted at BeginDispatch for exactly that request. The target verifies it
// itself, with its own replay store, and refuses anything without a valid
// one, so a request that did not pass PantherClaw is refused at the target.
const (
	actionTokenType = "pap-action+jwt" //nolint:gosec // G101: a JOSE type name, not a credential
	// maxTokenLife is the longest an action token may live (60 seconds).
	maxTokenLife = 60 * time.Second
	// skew tolerates clock differences with the Authority.
	skew = 5 * time.Second
	// jwksEvery is how often the verifier refetches the keys; an unknown
	// key id refetches at once, at most every jwksMinGap.
	jwksEvery  = 5 * time.Minute
	jwksMinGap = 10 * time.Second
)

// Errors of action-token verification: each is a refusal.
var (
	ErrNoActionToken      = errors.New("action_token_required")
	ErrActionTokenInvalid = errors.New("action_token_invalid")
	ErrActionTokenReplay  = errors.New("action_token_replayed")
)

// ActionVerifier verifies action tokens against the PantherClaw server's
// JWKS: the signature by an action_tokens key, the audience (this target's
// connection id), the lifetime, the hash of the exact body received, the
// operation and target the request is for, and a single use per token id.
type ActionVerifier struct {
	// JWKSURL is the server's /.well-known/pantherclaw/jwks.json.
	JWKSURL string
	// Audience is the connection id this target is reached through.
	Audience string
	// Client fetches the JWKS; nil uses a 5-second client.
	Client *http.Client
	// Now is the clock; nil is time.Now.
	Now func() time.Time

	mu      sync.Mutex
	v       *jws.Verifier
	kids    map[string]bool
	fetched time.Time
	seen    map[string]time.Time // token id → expiry
}

type actionClaims struct {
	Aud string `json:"aud"`
	Jti string `json:"jti"`
	Iat int64  `json:"iat"`
	Exp int64  `json:"exp"`
	Pap struct {
		V      int    `json:"v"`
		Txn    string `json:"txn"`
		BH     string `json:"bh"`
		Op     string `json:"op"`
		Target struct {
			Type string `json:"type"`
			ID   string `json:"id"`
		} `json:"target"`
	} `json:"pap"`
}

// Want is what the request is: the operation and the target it acts on.
type Want struct {
	Operation, TargetType, TargetID string
}

// Verify checks the action token of a request whose exact body is body,
// for the operation and target want, and spends it.
func (v *ActionVerifier) Verify(ctx context.Context, r *http.Request, body []byte, want Want) error {
	tok := r.Header.Get(HeaderAction)
	if tok == "" {
		return ErrNoActionToken
	}
	payload, err := v.verifySignature(ctx, tok)
	if err != nil {
		return err
	}
	var c actionClaims
	if err := json.Unmarshal(payload, &c); err != nil {
		return ErrActionTokenInvalid
	}
	now := v.now()
	sum := sha256.Sum256(body)
	iat, exp := time.Unix(c.Iat, 0), time.Unix(c.Exp, 0)
	switch {
	case c.Pap.V != 1 || c.Aud != v.Audience || c.Jti == "":
		return fmt.Errorf("%w: audience", ErrActionTokenInvalid)
	case !now.Before(exp.Add(skew)) || iat.After(now.Add(skew)) || exp.Sub(iat) > maxTokenLife:
		return fmt.Errorf("%w: lifetime", ErrActionTokenInvalid)
	case c.Pap.BH != hex.EncodeToString(sum[:]):
		return fmt.Errorf("%w: body", ErrActionTokenInvalid)
	case c.Pap.Op != want.Operation || c.Pap.Target.Type != want.TargetType || c.Pap.Target.ID != want.TargetID:
		return fmt.Errorf("%w: operation or target", ErrActionTokenInvalid)
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.seen == nil {
		v.seen = map[string]time.Time{}
	}
	for id, until := range v.seen {
		if now.After(until.Add(skew)) {
			delete(v.seen, id)
		}
	}
	if _, used := v.seen[c.Jti]; used {
		return ErrActionTokenReplay
	}
	v.seen[c.Jti] = exp
	return nil
}

func (v *ActionVerifier) now() time.Time {
	if v.Now != nil {
		return v.Now()
	}
	return time.Now()
}

// verifySignature verifies the JWS with the current keys, refetching them
// for a key id it does not know.
func (v *ActionVerifier) verifySignature(ctx context.Context, tok string) ([]byte, error) {
	kid, typ, err := jws.Unverified(tok)
	if err != nil || typ != actionTokenType {
		return nil, ErrActionTokenInvalid
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	now := v.now()
	if v.v == nil || now.Sub(v.fetched) > jwksEvery || (!v.kids[kid] && now.Sub(v.fetched) > jwksMinGap) {
		if err := v.fetchLocked(ctx); err != nil && v.v == nil {
			return nil, fmt.Errorf("%w: keys: %w", ErrActionTokenInvalid, err)
		}
	}
	payload, _, err := v.v.Verify(tok)
	if err != nil {
		return nil, ErrActionTokenInvalid
	}
	return payload, nil
}

func (v *ActionVerifier) fetchLocked(ctx context.Context) error {
	client := v.Client
	if client == nil {
		client = &http.Client{Timeout: 5 * time.Second}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, v.JWKSURL, nil)
	if err != nil {
		return err
	}
	res, err := client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = res.Body.Close() }()
	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("JWKS status %d", res.StatusCode)
	}
	var set struct {
		Keys []jws.JWK `json:"keys"`
	}
	if err := json.UnmarshalRead(io.LimitReader(res.Body, 64<<10), &set); err != nil {
		return err
	}
	pubs := map[string]ed25519.PublicKey{}
	for _, k := range set.Keys {
		// Only action-token keys, whose id is their own thumbprint: no other
		// PantherClaw key can mint a token this target accepts.
		if pub, err := k.Key(); err == nil && k.Kid == keys.KIDFor(keys.PurposeActionTokens, pub) {
			pubs[k.Kid] = pub
		}
	}
	vf, err := jws.NewVerifier(actionTokenType, pubs)
	if err != nil {
		return err
	}
	v.v, v.kids, v.fetched = vf, map[string]bool{}, v.now()
	for kid := range pubs {
		v.kids[kid] = true
	}
	return nil
}
