// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package trust

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/platform/crypto/jws"
	"github.com/katocxl/pantherclaw/internal/platform/rootkey"
)

var now = time.Date(2026, 10, 8, 12, 0, 0, 0, time.UTC)

// testRoot generates a throwaway package root (never the founder's key).
func testRoot(t *testing.T, purpose rootkey.Purpose) (*jws.Signer, Roots) {
	t.Helper()
	priv, kid, err := rootkey.Generate(purpose)
	if err != nil {
		t.Fatal(err)
	}
	s, err := jws.NewSigner(kid, priv)
	if err != nil {
		t.Fatal(err)
	}
	return s, Roots{kid: s.Public()}
}

var pkgBytes = []byte("format: 1\nname: pc.mock-payments\n")

func targetsFor(version int64, files map[string][]byte) Targets {
	t := Targets{Version: version, Expires: "2027-04-08T00:00:00Z", Targets: map[string]Target{}}
	for key, raw := range files {
		sum := sha256.Sum256(raw)
		t.Targets[key] = Target{Length: int64(len(raw)), Hashes: map[string]string{"sha256": hex.EncodeToString(sum[:])}}
	}
	return t
}

func sign(t *testing.T, s *jws.Signer, tg Targets) string {
	t.Helper()
	doc, err := Sign(tg, s)
	if err != nil {
		t.Fatal(err)
	}
	return doc
}

func TestHR123_SignedTargetsVerify(t *testing.T) {
	s, roots := testRoot(t, rootkey.PurposePackages)
	doc := sign(t, s, targetsFor(3, map[string][]byte{"pc.mock-payments@1.0.0": pkgBytes}))
	v, err := Verify(doc, roots, now)
	if err != nil {
		t.Fatal(err)
	}
	if v.Version != 3 || v.KID != s.KeyID() || len(v.PayloadDigest) != 64 {
		t.Fatalf("verified %+v", v)
	}
	if d, err := v.Match("pc.mock-payments", "1.0.0", pkgBytes); err != nil || !strings.HasPrefix(d, "sha256:") {
		t.Fatalf("Match: %q %v", d, err)
	}
	if got := rootkey.KID(rootkey.PurposePackages, s.Public()); got != RootKID(s.Public()) {
		t.Fatalf("pclaw-admin kid %q differs from the trust kid %q", got, RootKID(s.Public()))
	}
}

func TestT036_SignatureTamperIsRejected(t *testing.T) {
	s, roots := testRoot(t, rootkey.PurposePackages)
	other, _ := testRoot(t, rootkey.PurposePackages)
	tg := targetsFor(3, map[string][]byte{"pc.mock-payments@1.0.0": pkgBytes})
	doc := sign(t, s, tg)
	h, p, sig := split(doc)

	evil := targetsFor(9, map[string][]byte{"pc.mock-payments@1.0.0": []byte("evil")})
	evilDoc := sign(t, other, evil)
	_, evilPayload, _ := split(evilDoc)

	licenceSigner, _ := testRoot(t, rootkey.PurposeLicence)
	licenceDoc, err := licenceSigner.Sign(JOSEType, []byte(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	wrongTyp, err := s.Sign("pc-licence+jwt", []byte(p))
	if err != nil {
		t.Fatal(err)
	}
	none := b64(`{"alg":"none","kid":"`+s.KeyID()+`","typ":"`+JOSEType+`"}`) + "." + p + "."
	extraHeader := b64(`{"alg":"EdDSA","kid":"`+s.KeyID()+`","typ":"`+JOSEType+`","jwk":{}}`) + "." + p + "." + sig
	for name, d := range map[string]string{
		"payload swapped":    h + "." + evilPayload + "." + sig,
		"signature flipped":  h + "." + p + "." + flip(sig),
		"unknown key":        evilDoc,
		"licence root":       licenceDoc,
		"wrong typ":          wrongTyp,
		"alg none":           none,
		"embedded jwk":       extraHeader,
		"truncated":          h + "." + p,
		"garbage":            "not a jws",
		"trailing signature": doc + "." + sig,
	} {
		if _, err := Verify(d, roots, now); !errors.Is(err, ErrUntrusted) {
			t.Errorf("%s: err = %v, want ErrUntrusted", name, err)
		}
	}
	if _, err := Verify(doc, Roots{}, now); !errors.Is(err, ErrUntrusted) {
		t.Errorf("no embedded roots: %v", err)
	}
	if _, err := Sign(tg, licenceSigner); err == nil {
		t.Error("a licence root must not sign package metadata")
	}
}

func split(doc string) (h, p, s string) {
	parts := strings.Split(doc, ".")
	return parts[0], parts[1], parts[2]
}

func b64(s string) string { return base64.RawURLEncoding.EncodeToString([]byte(s)) }

func flip(s string) string {
	b, _ := base64.RawURLEncoding.DecodeString(s)
	b[0] ^= 1
	return base64.RawURLEncoding.EncodeToString(b)
}

func TestHR123_MetadataExpires(t *testing.T) {
	s, roots := testRoot(t, rootkey.PurposePackages)
	tg := targetsFor(1, map[string][]byte{"pc.mock-payments@1.0.0": pkgBytes})
	doc := sign(t, s, tg)
	if _, err := Verify(doc, roots, time.Date(2027, 4, 8, 0, 0, 0, 0, time.UTC)); !errors.Is(err, ErrExpired) {
		t.Fatalf("at expiry: %v, want ErrExpired", err)
	}
	for _, exp := range []string{"2027-04-08T00:00:00+01:00", "2027-04-08", "soon"} {
		tg.Expires = exp
		if _, err := Sign(tg, s); !errors.Is(err, ErrUntrusted) {
			t.Errorf("expires %q: %v", exp, err)
		}
	}
}

func TestHR123_MetadataNeverRollsBack(t *testing.T) {
	s, roots := testRoot(t, rootkey.PurposePackages)
	files := map[string][]byte{"pc.mock-payments@1.0.0": pkgBytes}
	v5, _ := Verify(sign(t, s, targetsFor(5, files)), roots, now)
	v4, _ := Verify(sign(t, s, targetsFor(4, files)), roots, now)
	alt := targetsFor(5, files)
	alt.Expires = "2027-05-01T00:00:00Z"
	v5alt, _ := Verify(sign(t, s, alt), roots, now)
	last := &State{Version: v5.Version, PayloadDigest: v5.PayloadDigest}
	if err := CheckAdvance(last, v4); !errors.Is(err, ErrRollback) {
		t.Errorf("older version: %v", err)
	}
	if err := CheckAdvance(last, v5alt); !errors.Is(err, ErrRollback) {
		t.Errorf("same version, other content: %v", err)
	}
	if err := CheckAdvance(last, v5); err != nil {
		t.Errorf("same metadata again: %v", err)
	}
	if err := CheckAdvance(nil, v4); err != nil {
		t.Errorf("first metadata: %v", err)
	}
}

func TestT036_PackageBytesMustMatchTheSignedHash(t *testing.T) {
	s, roots := testRoot(t, rootkey.PurposePackages)
	v, err := Verify(sign(t, s, targetsFor(1, map[string][]byte{"pc.mock-payments@1.0.0": pkgBytes})), roots, now)
	if err != nil {
		t.Fatal(err)
	}
	for name, c := range map[string]struct {
		pkg, version string
		raw          []byte
	}{
		"one byte changed": {"pc.mock-payments", "1.0.0", append([]byte("#"), pkgBytes[1:]...)},
		"appended":         {"pc.mock-payments", "1.0.0", append(append([]byte{}, pkgBytes...), '\n')},
		"unlisted version": {"pc.mock-payments", "1.0.1", pkgBytes},
		"unlisted package": {"pc.other", "1.0.0", pkgBytes},
	} {
		if _, err := v.Match(c.pkg, c.version, c.raw); !errors.Is(err, ErrUntrusted) {
			t.Errorf("%s: %v, want ErrUntrusted", name, err)
		}
	}
}

func TestTargetsShape(t *testing.T) {
	s, _ := testRoot(t, rootkey.PurposePackages)
	for name, tg := range map[string]Targets{
		"no targets":     {Version: 1, Expires: "2027-01-01T00:00:00Z"},
		"version zero":   targetsFor(0, map[string][]byte{"pc.a@1.0.0": pkgBytes}),
		"bad key":        targetsFor(1, map[string][]byte{"pc.a-1.0.0": pkgBytes}),
		"bad version":    targetsFor(1, map[string][]byte{"pc.a@1.0": pkgBytes}),
		"empty file":     targetsFor(1, map[string][]byte{"pc.a@1.0.0": {}}),
		"too many files": many(MaxTargets + 1),
	} {
		if _, err := Sign(tg, s); !errors.Is(err, ErrUntrusted) {
			t.Errorf("%s: %v, want ErrUntrusted", name, err)
		}
	}
}

func many(n int) Targets {
	files := map[string][]byte{}
	for i := range n {
		files["pc.a@1.0."+strconv.Itoa(i)] = pkgBytes
	}
	return targetsFor(1, files)
}

func TestParseRoots(t *testing.T) {
	r, err := EmbeddedRoots()
	if err != nil || len(r) != 0 {
		t.Fatalf("embedded roots must parse and stay empty until Day-0 item 6: %v %v", r, err)
	}
	pub, _, _ := ed25519.GenerateKey(nil)
	good := jws.PublicJWK(pub, RootKID(pub))
	bad := jws.PublicJWK(pub, "packages-root-chosen-by-attacker")
	for _, c := range []struct {
		doc string
		ok  bool
	}{
		{`{"keys":[` + jwk(good) + `]}`, true},
		{`{"keys":[` + jwk(bad) + `]}`, false},
		{`{"keys":[],"extra":1}`, false},
	} {
		if _, err := ParseRoots([]byte(c.doc)); (err == nil) != c.ok {
			t.Errorf("%s: err = %v", c.doc, err)
		}
	}
}

func jwk(k jws.JWK) string {
	return `{"kty":"` + k.Kty + `","crv":"` + k.Crv + `","x":"` + k.X + `","kid":"` + k.Kid + `"}`
}
