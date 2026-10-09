// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package trust

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json/v2"
	"errors"
	"strings"
	"testing"

	"github.com/katocxl/pantherclaw/internal/platform/crypto/jws"
	"github.com/katocxl/pantherclaw/internal/platform/rootkey"
)

// testOrgKey generates a throwaway org package-signing key.
func testOrgKey(t *testing.T) *jws.Signer {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	s, err := jws.NewSigner(OrgKID(pub), priv)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

var orgPkg = []byte("format: 1\nname: acme.billing\n")

func TestHR162_OrgKeySignsTheOrgsOwnPackages(t *testing.T) {
	s := testOrgKey(t)
	doc := sign(t, s, targetsFor(1, map[string][]byte{"acme.billing@1.0.0": orgPkg}))
	v, err := Verify(doc, Roots{s.KeyID(): s.Public()}, now)
	if err != nil {
		t.Fatal(err)
	}
	if !IsOrgKID(v.KID) || IsOrgKID(RootKID(s.Public())) || OrgKID(s.Public()) == RootKID(s.Public()) {
		t.Fatalf("kid %q: org and root kids must differ by prefix", v.KID)
	}
	if got := rootkey.KID(rootkey.PurposeOrgPackages, s.Public()); got != v.KID {
		t.Fatalf("pclaw's key file kid %q differs from the trust kid %q", got, v.KID)
	}
	if _, err := v.Match("acme.billing", "1.0.0", orgPkg); err != nil {
		t.Fatal(err)
	}
	// The org key is not a package root, and a root's roots never hold an
	// org kid.
	_, roots := testRoot(t, rootkey.PurposePackages)
	if _, err := Verify(doc, roots, now); !errors.Is(err, ErrUntrusted) {
		t.Fatalf("org-signed targets against the package roots: %v", err)
	}
}

func TestHR162_OrgKeyNeverSignsReservedNames(t *testing.T) {
	s := testOrgKey(t)
	tg := targetsFor(1, map[string][]byte{"acme.billing@1.0.0": orgPkg, "pc.mock-payments@9.0.0": pkgBytes})
	if _, err := Sign(tg, s); !errors.Is(err, ErrUntrusted) || !strings.Contains(err.Error(), "pc.mock-payments@9.0.0") {
		t.Fatalf("Sign with a reserved name: %v", err)
	}
	// A document signed outside Sign (a modified tool) is refused on import.
	tg.Type, tg.Spec = "targets", Spec
	payload, err := json.Marshal(tg, json.Deterministic(true))
	if err != nil {
		t.Fatal(err)
	}
	doc, err := s.Sign(JOSEType, payload)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(doc, Roots{s.KeyID(): s.Public()}, now); !errors.Is(err, ErrUntrusted) {
		t.Fatalf("Verify with a reserved name: %v", err)
	}
	// The package root may sign reserved names.
	root, roots := testRoot(t, rootkey.PurposePackages)
	if _, err := Verify(sign(t, root, tg), roots, now); err != nil {
		t.Fatal(err)
	}
}

func TestHR162_SignerKidMustBeDerivedFromItsKey(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	other, _, _ := ed25519.GenerateKey(rand.Reader)
	tg := targetsFor(1, map[string][]byte{"acme.billing@1.0.0": orgPkg})
	for _, kid := range []string{OrgKID(other), OrgKIDPrefix + "x", "packages-root-" + jws.Thumbprint(other)[:22], rootkey.KID(rootkey.PurposeLicence, pub)} {
		s, err := jws.NewSigner(kid, priv)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := Sign(tg, s); err == nil {
			t.Errorf("signer kid %q accepted", kid)
		}
	}
}

func TestHR162_ParseOrgKey(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	jwk := func(kid, use string) []byte {
		k := jws.PublicJWK(pub, kid)
		k.Use = use
		b, err := json.Marshal(k)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	for name, b := range map[string][]byte{"with kid": jwk(OrgKID(pub), "sig"), "without kid": jwk("", "")} {
		kid, got, err := ParseOrgKey(b)
		if err != nil || kid != OrgKID(pub) || !got.Equal(pub) {
			t.Errorf("%s: %q %v", name, kid, err)
		}
	}
	for name, b := range map[string][]byte{
		"root kid":      jwk(RootKID(pub), "sig"),
		"other kid":     jwk(OrgKIDPrefix+"AAAAAAAAAAAAAAAAAAAAAA", "sig"),
		"encryption":    jwk("", "enc"),
		"rsa":           []byte(`{"kty":"RSA","n":"AQAB","e":"AQAB"}`),
		"short key":     []byte(`{"kty":"OKP","crv":"Ed25519","x":"AAAA"}`),
		"extra member":  []byte(`{"kty":"OKP","crv":"Ed25519","x":"` + jws.PublicJWK(pub, "").X + `","d":"secret"}`),
		"not json":      []byte(`kty: OKP`),
		"duplicate key": []byte(`{"kty":"OKP","kty":"OKP","crv":"Ed25519","x":"` + jws.PublicJWK(pub, "").X + `"}`),
	} {
		if _, _, err := ParseOrgKey(b); !errors.Is(err, ErrUntrusted) {
			t.Errorf("%s: %v", name, err)
		}
	}
}
