// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package licence

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/billing/domain"
	"github.com/katocxl/pantherclaw/internal/platform/crypto/jws"
)

func rootSigner(t *testing.T) (*jws.Signer, Roots) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	s, err := jws.NewSigner(RootKID(pub), priv)
	if err != nil {
		t.Fatal(err)
	}
	return s, Roots{RootKID(pub): pub}
}

func testClaims() domain.Claims {
	at := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	return domain.Claims{
		Version: 1, LicenceID: "lic-1", Licensee: "Acme Ltd", CustomerID: "cus_1", Edition: domain.Business,
		MaxAgents: 100, MaxOrgs: 5, IssuedAt: at, NotBefore: at, ExpiresAt: at.AddDate(1, 0, 0),
	}
}

func TestSignVerifyRoundTrip(t *testing.T) {
	s, roots := rootSigner(t)
	doc, err := Sign(testClaims(), s)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(doc, []byte("-----BEGIN PANTHERCLAW LICENCE-----")) {
		t.Fatalf("unexpected armor:\n%s", doc)
	}
	c, err := Verify(doc, roots)
	if err != nil {
		t.Fatal(err)
	}
	if c != testClaims() {
		t.Fatalf("claims = %+v, want %+v", c, testClaims())
	}
}

func TestT034_ForgedOrTamperedLicencesAreInvalid(t *testing.T) {
	s, roots := rootSigner(t)
	other, _ := rootSigner(t)
	good, _ := Sign(testClaims(), s)
	forged, _ := Sign(testClaims(), other)

	// Raise the agent limit in the payload while keeping the signature.
	block, _ := pem.Decode(good)
	parts := strings.Split(string(block.Bytes), ".")
	payload, _ := base64.RawURLEncoding.DecodeString(parts[1])
	raised := strings.Replace(string(payload), `"max_agents":100`, `"max_agents":100000`, 1)
	tampered := pem.EncodeToMemory(&pem.Block{Type: PEMType, Bytes: []byte(parts[0] + "." + base64.RawURLEncoding.EncodeToString([]byte(raised)) + "." + parts[2])})

	// A permit-typed token signed by the right key must not pass as a licence.
	permitTok, _ := s.Sign("pap-permit+jwt", payload)
	wrongTyp := pem.EncodeToMemory(&pem.Block{Type: PEMType, Bytes: []byte(permitTok)})

	withHeaders := pem.EncodeToMemory(&pem.Block{Type: PEMType, Headers: map[string]string{"X": "y"}, Bytes: block.Bytes})
	wrongPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: block.Bytes})

	for name, doc := range map[string][]byte{
		"other signer":   forged,
		"tampered":       tampered,
		"wrong typ":      wrongTyp,
		"pem headers":    withHeaders,
		"wrong pem type": wrongPEM,
		"trailing data":  append(bytes.Clone(good), []byte("extra")...),
		"two licences":   append(bytes.Clone(good), good...),
		"empty":          nil,
		"oversized":      bytes.Repeat([]byte("a"), MaxDocumentBytes+1),
	} {
		if _, err := Verify(doc, roots); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: accepted (err %v)", name, err)
		}
	}
}

func TestUnknownClaimsAreRejected(t *testing.T) {
	s, roots := rootSigner(t)
	tok, _ := s.Sign(JOSEType, []byte(`{"v":1,"lid":"l","sub":"s","cid":"c","edition":"team","max_agents":1,"max_orgs":1,"iat":1,"nbf":1,"exp":2,"admin":true}`))
	doc := pem.EncodeToMemory(&pem.Block{Type: PEMType, Bytes: []byte(tok)})
	if _, err := Verify(doc, roots); !errors.Is(err, ErrInvalid) {
		t.Fatalf("unknown claim accepted: %v", err)
	}
}

func TestHR063_EmbeddedRootsArePublicOnly(t *testing.T) {
	roots, err := EmbeddedRoots()
	if err != nil {
		t.Fatalf("embedded roots do not parse: %v", err)
	}
	if bytes.Contains(embeddedRoots, []byte(`"d"`)) {
		t.Fatal("roots.json contains private key material")
	}
	if len(roots) == 0 {
		// Until the founder commits the offline public key, no licence verifies.
		s, _ := rootSigner(t)
		doc, _ := Sign(testClaims(), s)
		if _, err := Verify(doc, roots); !errors.Is(err, ErrInvalid) {
			t.Fatal("licence verified without any embedded root")
		}
	}
}

func TestParseRootsRejects(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	x := base64.RawURLEncoding.EncodeToString(pub)
	for name, doc := range map[string]string{
		"private member": `{"keys":[{"kty":"OKP","crv":"Ed25519","x":"` + x + `","d":"AAAA","kid":"` + RootKID(pub) + `"}]}`,
		"kid mismatch":   `{"keys":[{"kty":"OKP","crv":"Ed25519","x":"` + x + `","kid":"licence-root-other"}]}`,
		"wrong curve":    `{"keys":[{"kty":"EC","crv":"P-256","x":"` + x + `","kid":"` + RootKID(pub) + `"}]}`,
		"not json":       `nope`,
	} {
		if _, err := ParseRoots([]byte(doc)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestSignRefusesNonRootKeys(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	s, _ := jws.NewSigner("permits-abc", priv)
	if _, err := Sign(testClaims(), s); err == nil {
		t.Fatal("licence signed with a non-root key")
	}
	r, _ := rootSigner(t)
	bad := testClaims()
	bad.Edition = domain.Community
	if _, err := Sign(bad, r); err == nil {
		t.Fatal("invalid claims signed")
	}
}
