// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package issuerkeys_test

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/identity/adapters/issuerkeys"
	"github.com/katocxl/pantherclaw/internal/platform/httpx"
)

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

type issuer struct {
	srv       *httptest.Server
	key       *rsa.PrivateKey
	jwksHits  atomic.Int32
	jwksURI   string
	jwksExtra string
}

func newIssuer(t *testing.T, bits int) *issuer {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		t.Fatal(err)
	}
	is := &issuer{key: key}
	mux := http.NewServeMux()
	is.srv = httptest.NewTLSServer(mux)
	t.Cleanup(is.srv.Close)
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		uri := is.jwksURI
		if uri == "" {
			uri = is.srv.URL + "/jwks"
		}
		_, _ = w.Write([]byte(`{"issuer":"` + is.srv.URL + `","jwks_uri":"` + uri + `"}`))
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) {
		is.jwksHits.Add(1)
		e := big.NewInt(int64(key.E)).Bytes()
		_, _ = w.Write([]byte(`{"keys":[{"kty":"RSA","kid":"k1","use":"sig","alg":"RS256","n":"` + b64(key.N.Bytes()) +
			`","e":"` + b64(e) + `"}` + is.jwksExtra + `]}`))
	})
	return is
}

// token signs header and payload JSON with RS256.
func (is *issuer) token(t *testing.T, header string) string {
	t.Helper()
	signing := b64([]byte(header)) + "." + b64([]byte(`{"iss":"x","repository_id":"1"}`))
	sum := sha256.Sum256([]byte(signing))
	sig, err := rsa.SignPKCS1v15(rand.Reader, is.key, crypto.SHA256, sum[:])
	if err != nil {
		t.Fatal(err)
	}
	return signing + "." + b64(sig)
}

func (is *issuer) client(allowLoopback bool) *http.Client {
	pool := x509.NewCertPool()
	pool.AddCert(is.srv.Certificate())
	cfg := httpx.EgressConfig{RootCAs: pool}
	if allowLoopback {
		cfg.AllowedPrefixes = []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}
	}
	return httpx.NewEgressClient(cfg)
}

type fakeClock struct{ t time.Time }

func (c *fakeClock) now() time.Time { return c.t }

func newFetcher(t *testing.T, is *issuer, clk *fakeClock, allow bool) *issuerkeys.Fetcher {
	t.Helper()
	f, err := issuerkeys.New(is.client(allow), is.srv.URL, clk.now)
	if err != nil {
		t.Fatal(err)
	}
	return f
}

const goodHeader = `{"typ":"JWT","alg":"RS256","x5t":"abc","kid":"k1"}`

// TestHR142_KeysComeFromTheIssuerOnlyThroughEgressGuards.
func TestHR142_KeysComeFromTheIssuerOnlyThroughEgressGuards(t *testing.T) {
	is := newIssuer(t, 2048)
	clk := &fakeClock{t: time.Unix(1791457200, 0)}
	f := newFetcher(t, is, clk, true)
	ctx := context.Background()
	payload, err := f.Verify(ctx, is.token(t, goodHeader))
	if err != nil || !strings.Contains(string(payload), "repository_id") {
		t.Fatalf("valid token: %s, %v", payload, err)
	}
	for name, h := range map[string]string{
		"embedded jwk":   `{"alg":"RS256","kid":"k1","jwk":{"kty":"RSA"}}`,
		"jku":            `{"alg":"RS256","kid":"k1","jku":"https://evil.test/jwks"}`,
		"x5c":            `{"alg":"RS256","kid":"k1","x5c":["MII"]}`,
		"crit":           `{"alg":"RS256","kid":"k1","crit":["exp"]}`,
		"alg none":       `{"alg":"none","kid":"k1"}`,
		"HS256":          `{"alg":"HS256","kid":"k1"}`,
		"no kid":         `{"alg":"RS256"}`,
		"duplicate alg":  `{"alg":"RS256","alg":"none","kid":"k1"}`,
		"other kid lies": `{"alg":"RS256","kid":"k2"}`,
	} {
		if _, err := f.Verify(ctx, is.token(t, h)); !errors.Is(err, issuerkeys.ErrUnverified) && err == nil {
			t.Errorf("%s: verified", name)
		}
	}
	// Unknown kids refetch at most once a minute; the cache lasts 15 minutes.
	hits := is.jwksHits.Load()
	unknown := is.token(t, `{"alg":"RS256","kid":"rotated"}`)
	_, _ = f.Verify(ctx, unknown)
	_, _ = f.Verify(ctx, unknown)
	if got := is.jwksHits.Load() - hits; got > 1 {
		t.Fatalf("%d refetches within a minute, want at most 1", got)
	}
	clk.t = clk.t.Add(61 * time.Second)
	_, _ = f.Verify(ctx, unknown)
	clk.t = clk.t.Add(issuerkeys.CacheFor)
	before := is.jwksHits.Load()
	if _, err := f.Verify(ctx, is.token(t, goodHeader)); err != nil || is.jwksHits.Load() != before+1 {
		t.Fatalf("expired cache was not refreshed (%v)", err)
	}
	// An unreachable issuer fails closed once the cache has expired.
	is.srv.Close()
	clk.t = clk.t.Add(issuerkeys.CacheFor)
	if _, err := f.Verify(ctx, is.token(t, goodHeader)); err == nil {
		t.Fatal("an unreachable issuer verified a token from an expired cache")
	}
}

func TestHR142_KeySourcesAreConstrained(t *testing.T) {
	ctx := context.Background()
	clk := &fakeClock{t: time.Unix(1791457200, 0)}
	// A private address is refused unless explicitly allowed.
	is := newIssuer(t, 2048)
	if _, err := newFetcher(t, is, clk, false).Verify(ctx, is.token(t, goodHeader)); err == nil {
		t.Error("fetched keys from a loopback address without an allowed prefix")
	}
	// The JWKS must live on the issuer's own host.
	other := newIssuer(t, 2048)
	other.jwksURI = "https://evil.test/jwks"
	if _, err := newFetcher(t, other, clk, true).Verify(ctx, other.token(t, goodHeader)); err == nil {
		t.Error("followed a JWKS URI on another host")
	}
	// Keys under 2048 bits are ignored.
	weak := newIssuer(t, 1024)
	if _, err := newFetcher(t, weak, clk, true).Verify(ctx, weak.token(t, goodHeader)); err == nil {
		t.Error("accepted a 1024-bit key")
	}
	// Oversized key documents are refused.
	big := newIssuer(t, 2048)
	big.jwksExtra = strings.Repeat(`,{"kty":"oct","k":"`+strings.Repeat("A", 1000)+`"}`, 80)
	if _, err := newFetcher(t, big, clk, true).Verify(ctx, big.token(t, goodHeader)); err == nil {
		t.Error("accepted a JWKS over 64 KiB")
	}
	// Redirects are not followed.
	redirect := httptest.NewTLSServer(http.RedirectHandler("https://evil.test/", http.StatusFound))
	defer redirect.Close()
	pool := x509.NewCertPool()
	pool.AddCert(redirect.Certificate())
	f, _ := issuerkeys.New(httpx.NewEgressClient(httpx.EgressConfig{
		RootCAs: pool, AllowedPrefixes: []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")},
	}), redirect.URL, clk.now)
	if _, err := f.Verify(ctx, is.token(t, goodHeader)); err == nil {
		t.Error("followed a redirect")
	}
	if _, err := issuerkeys.New(http.DefaultClient, "http://token.actions.githubusercontent.com", nil); err == nil { //nolint:forbidigo // the client is never used
		t.Error("accepted an http issuer")
	}
}
