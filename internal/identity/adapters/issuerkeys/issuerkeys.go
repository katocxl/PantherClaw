// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package issuerkeys verifies GitHub Actions OIDC token signatures with the
// issuer's published keys (HR-142, ADR-0018). Keys come from the issuer's
// discovery document and JWKS over TLS through the egress-guarded client
// only (no redirects, no proxy variables, no private addresses); the JWKS
// URI must be on the issuer's own host; documents are size-capped; at most
// 20 RSA keys of at least 2048 bits are kept, for at most 15 minutes; and an
// unknown kid triggers at most one refetch per minute. An unreachable
// issuer fails closed.
package issuerkeys

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v4"
)

// Limits (HR-142).
const (
	MaxDocument  = 64 << 10
	MaxKeys      = 20
	CacheFor     = 15 * time.Minute
	MissInterval = time.Minute
	MaxToken     = 16 << 10
)

// ErrUnverified is returned for every token that does not verify; the
// detail is for logs only.
var ErrUnverified = errors.New("issuerkeys: token not verified")

// Fetcher caches one issuer's signing keys.
type Fetcher struct {
	client *http.Client
	issuer string
	now    func() time.Time

	mu        sync.Mutex
	keys      map[string]*rsa.PublicKey
	fetchedAt time.Time
	lastMiss  time.Time
}

// New returns a fetcher for issuer (https only) using client, which must be
// an egress client (httpx.NewEgressClient).
func New(client *http.Client, issuer string, now func() time.Time) (*Fetcher, error) {
	u, err := url.Parse(issuer)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return nil, fmt.Errorf("issuerkeys: issuer %q must be an https URL", issuer)
	}
	if now == nil {
		now = time.Now
	}
	return &Fetcher{client: client, issuer: strings.TrimSuffix(issuer, "/"), now: now}, nil
}

// Verify checks compact's RS256 signature with the issuer's key named by
// its kid and returns the payload. Claims are checked by the preset.
func (f *Fetcher) Verify(ctx context.Context, compact string) ([]byte, error) {
	if len(compact) > MaxToken {
		return nil, fmt.Errorf("%w: size", ErrUnverified)
	}
	if err := checkHeader(compact); err != nil {
		return nil, err
	}
	obj, err := jose.ParseSigned(compact, []jose.SignatureAlgorithm{jose.RS256})
	if err != nil || len(obj.Signatures) != 1 {
		return nil, fmt.Errorf("%w: parse", ErrUnverified)
	}
	h := obj.Signatures[0].Protected
	if h.KeyID == "" {
		return nil, fmt.Errorf("%w: header", ErrUnverified)
	}
	key, err := f.key(ctx, h.KeyID)
	if err != nil {
		return nil, err
	}
	payload, err := obj.Verify(key)
	if err != nil {
		return nil, fmt.Errorf("%w: signature", ErrUnverified)
	}
	return payload, nil
}

// checkHeader accepts only the members a GitHub token header carries: keys
// never come from the token (no jwk, jku, x5u, x5c) and nothing is critical.
func checkHeader(compact string) error {
	seg, _, ok := strings.Cut(compact, ".")
	if !ok {
		return fmt.Errorf("%w: malformed", ErrUnverified)
	}
	raw, err := base64.RawURLEncoding.Strict().DecodeString(seg)
	if err != nil {
		return fmt.Errorf("%w: header encoding", ErrUnverified)
	}
	var h map[string]any
	if err := json.Unmarshal(raw, &h); err != nil {
		return fmt.Errorf("%w: header", ErrUnverified)
	}
	for k := range h {
		switch k {
		case "alg", "kid", "typ", "x5t":
		default:
			return fmt.Errorf("%w: header member %q", ErrUnverified, k)
		}
	}
	if h["alg"] != "RS256" {
		return fmt.Errorf("%w: algorithm", ErrUnverified)
	}
	return nil
}

// key returns the key for kid, refreshing a stale cache, or the cache on a
// miss at most once per MissInterval.
func (f *Fetcher) key(ctx context.Context, kid string) (*rsa.PublicKey, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	now := f.now()
	stale := f.keys == nil || now.Sub(f.fetchedAt) >= CacheFor
	k, ok := f.keys[kid]
	if !stale && ok {
		return k, nil
	}
	if !stale && !ok {
		if now.Sub(f.lastMiss) < MissInterval {
			return nil, fmt.Errorf("%w: unknown kid", ErrUnverified)
		}
		f.lastMiss = now
	}
	keys, err := f.fetch(ctx)
	if err != nil {
		if stale {
			f.keys = nil // an issuer that cannot be reached fails closed once the cache expired
		}
		return nil, err
	}
	f.keys, f.fetchedAt = keys, now
	if k, ok := keys[kid]; ok {
		return k, nil
	}
	return nil, fmt.Errorf("%w: unknown kid", ErrUnverified)
}

func (f *Fetcher) get(ctx context.Context, u string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := f.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("issuerkeys: fetch: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("issuerkeys: fetch %s: status %d", u, resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, MaxDocument+1))
	if err != nil || len(b) > MaxDocument {
		return nil, fmt.Errorf("issuerkeys: fetch %s: document too large or unreadable", u)
	}
	return b, nil
}

func (f *Fetcher) fetch(ctx context.Context) (map[string]*rsa.PublicKey, error) {
	raw, err := f.get(ctx, f.issuer+"/.well-known/openid-configuration")
	if err != nil {
		return nil, err
	}
	var disc struct {
		Issuer  string `json:"issuer"`
		JWKSURI string `json:"jwks_uri"`
	}
	if err := json.Unmarshal(raw, &disc); err != nil {
		return nil, fmt.Errorf("issuerkeys: discovery: %w", err)
	}
	ju, err := url.Parse(disc.JWKSURI)
	iu, _ := url.Parse(f.issuer)
	if disc.Issuer != f.issuer || err != nil || ju.Scheme != "https" || !strings.EqualFold(ju.Host, iu.Host) {
		return nil, errors.New("issuerkeys: discovery must name this issuer and a JWKS URI on its own https host")
	}
	raw, err = f.get(ctx, disc.JWKSURI)
	if err != nil {
		return nil, err
	}
	var set struct {
		Keys []struct {
			Kty string `json:"kty"`
			Kid string `json:"kid"`
			Use string `json:"use"`
			Alg string `json:"alg"`
			N   string `json:"n"`
			E   string `json:"e"`
		} `json:"keys"`
	}
	if err := json.Unmarshal(raw, &set); err != nil {
		return nil, fmt.Errorf("issuerkeys: jwks: %w", err)
	}
	out := map[string]*rsa.PublicKey{}
	for _, k := range set.Keys {
		if len(out) == MaxKeys {
			break
		}
		if k.Kty != "RSA" || k.Kid == "" || (k.Use != "" && k.Use != "sig") || (k.Alg != "" && k.Alg != "RS256") {
			continue
		}
		pub, err := rsaKey(k.N, k.E)
		if err != nil || pub.N.BitLen() < 2048 {
			continue
		}
		out[k.Kid] = pub
	}
	if len(out) == 0 {
		return nil, errors.New("issuerkeys: no usable keys")
	}
	return out, nil
}

func rsaKey(n, e string) (*rsa.PublicKey, error) {
	nb, err := base64.RawURLEncoding.DecodeString(n)
	if err != nil {
		return nil, err
	}
	eb, err := base64.RawURLEncoding.DecodeString(e)
	if err != nil || len(eb) == 0 || len(eb) > 4 {
		return nil, errors.New("exponent")
	}
	exp := 0
	for _, b := range eb {
		exp = exp<<8 | int(b)
	}
	pub := &rsa.PublicKey{E: exp}
	pub.N = new(big.Int).SetBytes(nb)
	return pub, nil
}
