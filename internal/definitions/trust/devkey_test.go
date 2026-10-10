// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package trust

import (
	"encoding/json/v2"
	"errors"
	"strings"
	"testing"

	"github.com/katocxl/pantherclaw/internal/platform/crypto/jws"
	"github.com/katocxl/pantherclaw/internal/platform/rootkey"
)

func jwks(t *testing.T, keys ...jws.JWK) []byte {
	t.Helper()
	b, err := json.Marshal(struct {
		Keys []jws.JWK `json:"keys"`
	}{keys})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestHR163_DevKeyIsNeverAPackageRoot: the development package key has its
// own kid, which roots.json and --roots refuse; it verifies only against
// itself, signs PantherClaw's reserved names like a root, and is routed to
// the root set rather than to an org's keys.
func TestHR163_DevKeyIsNeverAPackageRoot(t *testing.T) {
	dev, devRoots := testRoot(t, rootkey.PurposeDevPackages)
	kid := dev.KeyID()
	if !strings.HasPrefix(kid, DevKIDPrefix) || kid != DevKID(dev.Public()) || !IsDevKID(kid) || IsOrgKID(kid) {
		t.Fatalf("development kid %q", kid)
	}
	pub := jws.PublicJWK(dev.Public(), kid)
	if _, err := ParseRoots(jwks(t, pub)); err == nil {
		t.Fatal("a development key was accepted as a package root")
	}
	got, err := ParseDevKey(jwks(t, pub))
	if err != nil || len(got) != 1 || !got[kid].Equal(dev.Public()) {
		t.Fatalf("ParseDevKey = %v, %v", got, err)
	}

	root, roots := testRoot(t, rootkey.PurposePackages)
	asRoot := jws.PublicJWK(dev.Public(), RootKID(dev.Public()))
	withPrivate := []byte(strings.Replace(string(jwks(t, pub)), `"x":`, `"d":"AAAA","x":`, 1))
	for name, b := range map[string][]byte{
		"no key":               jwks(t),
		"two keys":             jwks(t, pub, jws.PublicJWK(root.Public(), root.KeyID())),
		"a package root":       jwks(t, jws.PublicJWK(root.Public(), root.KeyID())),
		"relabelled as a root": jwks(t, asRoot),
		"an org kid":           jwks(t, jws.PublicJWK(dev.Public(), OrgKID(dev.Public()))),
		"a private member":     withPrivate,
		"not a jwks":           []byte(`{"kty":"OKP"}`),
	} {
		if _, err := ParseDevKey(b); err == nil {
			t.Errorf("%s: accepted as a development key", name)
		}
	}

	doc := sign(t, dev, targetsFor(2, map[string][]byte{"pc.mock-payments@1.0.0": pkgBytes}))
	if v, err := Verify(doc, devRoots, now); err != nil || v.KID != kid {
		t.Fatalf("Verify with the development key = %v, %v", v.KID, err)
	}
	embedded, err := EmbeddedRoots()
	if err != nil {
		t.Fatal(err)
	}
	for name, r := range map[string]Roots{"embedded roots": embedded, "another root": roots} {
		if _, err := Verify(doc, r, now); !errors.Is(err, ErrUntrusted) {
			t.Errorf("development-signed targets against %s: %v", name, err)
		}
	}
}
