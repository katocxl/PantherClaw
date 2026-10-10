// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package note

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/mldsa"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"strings"
	"testing"

	"github.com/katocxl/pantherclaw/internal/evidence/merkle"
)

func b64(t testing.TB, s string) []byte {
	t.Helper()
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// Known answer from golang.org/x/mod/sumdb/note (the reference
// implementation of the format): key, text and the exact signed note.
const (
	goSKey = "AYEKFALVFGyNhPJEMzD1QIDr+Y7hfZx09iUvxdXHKDFz" // 0x01 ‖ Ed25519 seed (PRIVATE+KEY+PeterNeumann+c74f20a3+…)
	goVKey = "ARpc2QcUPDhMQegwxbzhKqiBfsVkmqq/LDE4izWy10TW" // 0x01 ‖ public key (PeterNeumann+c74f20a3+…)
	goText = "If you think cryptography is the answer to your problem,\nthen you don't know what your problem is.\n"
	goSig  = "x08go/ZJkuBS9UG/SffcvIAQxVBtiFupLLr8pAcElZInNIuGUgYN1FFYC2pZSNXgKvqfqdngotpRZb6KE6RyyBwJnAM="
)

func goNote() []byte { return []byte(goText + "\n" + emDash + " PeterNeumann " + goSig + "\n") }

func TestHR194_SignedNoteKnownAnswerEd25519(t *testing.T) {
	seed := b64(t, goSKey)
	if seed[0] != TypeEd25519 {
		t.Fatal("vector is not an Ed25519 key")
	}
	priv := ed25519.NewKeyFromSeed(seed[1:])
	s, err := NewEd25519Signer("PeterNeumann", priv)
	if err != nil {
		t.Fatal(err)
	}
	if s.KeyID() != 0xc74f20a3 {
		t.Fatalf("key id = %08x, want c74f20a3", s.KeyID())
	}
	got, err := Sign(goText, s)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, goNote()) {
		t.Fatalf("signed note:\n%s\nwant:\n%s", got, goNote())
	}
	vk := b64(t, goVKey)
	v, err := NewEd25519Verifier("PeterNeumann", vk[1:])
	if err != nil {
		t.Fatal(err)
	}
	n, verified, err := Open(goNote(), v)
	if err != nil || n.Text != goText || len(verified) != 1 || !SignedBy(verified, v) {
		t.Fatalf("open: %v", err)
	}
}

// A checkpoint recorded from Sigstore's Rekor v2 staging log
// (log2025-alpha1.rekor.sigstage.dev, Ed25519 key from its
// trusted_root.json), from the sigstore-conformance test suite
// (rekor2-happy-path, Apache-2.0). It locks the key ID and the checkpoint
// format against a real log.
const (
	rekorOrigin     = "log2025-alpha1.rekor.sigstage.dev"
	rekorPublicKey  = "MCowBQYDK2VwAyEAPn+AREHoBaZ7wgS1zBqpxmLSGnyhxXj4lFxSdWVB8o8="
	rekorCheckpoint = rekorOrigin + "\n736\nrs1YPY0ydAV0lxgfrq5pE4oRpUJwo3syeps5+eGUTDI=\n\n"
	rekorSigLine    = " " + rekorOrigin + " 8w1amdbj1mjNN674dHAkD92+QZoEgBC7o0mXYSTRluDjQrOPjrps3zQB9ut+ShLepyZPsWBDi5IB3yXyjgjQT6OG9A8=\n"
)

func TestHR194_RekorV2CheckpointKnownAnswer(t *testing.T) {
	v, err := NewPKIXVerifier(rekorOrigin, b64(t, rekorPublicKey))
	if err != nil {
		t.Fatal(err)
	}
	// The log id in the trusted root is the full hash: 8w1amZ2S…
	if v.KeyID() != 0xf30d5a99 {
		t.Fatalf("key id = %08x", v.KeyID())
	}
	msg := []byte(rekorCheckpoint + emDash + rekorSigLine)
	c, verified, err := OpenCheckpoint(msg, rekorOrigin, v)
	if err != nil || len(verified) != 1 {
		t.Fatalf("open: %v", err)
	}
	if c.Size != 736 || base64.StdEncoding.EncodeToString(c.Root[:]) != "rs1YPY0ydAV0lxgfrq5pE4oRpUJwo3syeps5+eGUTDI=" {
		t.Fatalf("checkpoint = %+v", c)
	}
	// One changed byte of the text is rejected.
	bad := bytes.Replace(msg, []byte("\n736\n"), []byte("\n737\n"), 1)
	if _, _, err := OpenCheckpoint(bad, rekorOrigin, v); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("altered checkpoint: %v", err)
	}
}

// An ECDSA P-256 note signature made with OpenSSL 3.5 (`openssl dgst
// -sha256 -sign`), so the encoding (ASN.1 DER over SHA-256 of the text) and
// the key ID (SHA-256 of the PKIX key, first 4 bytes: ce453841) are checked
// against an independent implementation.
const (
	ecdsaPub  = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEG13Xl1F9wvOxJKEG2A1FAdyGfuhXvkAjmWAncWLi8Gr9xuqrOL6fQOd7xgQMdBHVW/hNdXYi6LH0FYPnKSAZRg=="
	ecdsaText = "example.com/log\n4\nPVz0SDVFXH/nfQJQyIcMJQK5XHBzQHWNKwhrBOFn0ys=\n"
	ecdsaSig  = "MEQCICnxrRE2W8nC+SZIl1twIheQgo1Gg397sVfOuEVLoj9HAiAgYBx48gUYnjoettLXW7tdpmn8Dr4NDUjE/t1LCMzEKw=="
)

func TestHR194_ECDSACheckpointKnownAnswer(t *testing.T) {
	v, err := NewPKIXVerifier("example.com/log", b64(t, ecdsaPub))
	if err != nil {
		t.Fatal(err)
	}
	if v.KeyID() != 0xce453841 {
		t.Fatalf("key id = %08x", v.KeyID())
	}
	n := &Note{Text: ecdsaText, Sigs: []Signature{{Name: "example.com/log", KeyID: v.KeyID(), Sig: b64(t, ecdsaSig)}}}
	c, verified, err := OpenCheckpoint(n.Encode(), "example.com/log", v)
	if err != nil || len(verified) != 1 || c.Size != 4 {
		t.Fatalf("open: %+v %v", c, err)
	}
	// Our own ECDSA signer round-trips through the same verifier.
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	s, _ := NewECDSASigner("example.com/log", priv)
	pv, _ := NewECDSAVerifier("example.com/log", &priv.PublicKey)
	msg, err := Sign(ecdsaText, s)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := Open(msg, pv); err != nil {
		t.Fatal(err)
	}
	if _, err := NewECDSAVerifier("x", &mustKey(t, elliptic.P384()).PublicKey); err == nil {
		t.Fatal("P-384 accepted")
	}
}

func mustKey(t *testing.T, c elliptic.Curve) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(c, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func ed25519Pair(t testing.TB, name string) (Signer, Verifier) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	s, err := NewEd25519Signer(name, priv)
	if err != nil {
		t.Fatal(err)
	}
	v, err := NewEd25519Verifier(name, pub)
	if err != nil {
		t.Fatal(err)
	}
	return s, v
}

// fixedSigner signs with a given name and key ID (a key that only shares a
// name or an ID with a known key).
type fixedSigner struct {
	name string
	id   uint32
}

func (f fixedSigner) Name() string                { return f.name }
func (f fixedSigner) KeyID() uint32               { return f.id }
func (f fixedSigner) Sign([]byte) ([]byte, error) { return bytes.Repeat([]byte{7}, 64), nil }

func TestHR194_SeveralSignaturesUnknownKeysIgnored(t *testing.T) {
	text := "pantherclaw.test/org/1\n3\n" + base64.StdEncoding.EncodeToString(make([]byte, 32)) + "\n"
	a, va := ed25519Pair(t, "log-a")
	b, vb := ed25519Pair(t, "log-b")
	sameName := fixedSigner{"log-a", va.KeyID() + 1} // shares only the name
	sameID := fixedSigner{"log-c", va.KeyID()}       // shares only the key ID
	msg, err := Sign(text, sameName, a, sameID, b)
	if err != nil {
		t.Fatal(err)
	}
	_, verified, err := Open(msg, va)
	if err != nil || len(verified) != 1 || !SignedBy(verified, va) || SignedBy(verified, vb) {
		t.Fatalf("open with one known key: %v %v", verified, err)
	}
	_, verified, err = Open(msg, va, vb)
	if err != nil || len(verified) != 2 {
		t.Fatalf("open with both keys: %v %v", verified, err)
	}
	_, other := ed25519Pair(t, "log-z")
	if _, _, err := Open(msg, other); !errors.Is(err, ErrUnverified) {
		t.Fatalf("no known key: %v", err)
	}
	// A known key's signature that fails rejects the note, even when another
	// known key's signature verifies.
	n, err := Parse(msg)
	if err != nil {
		t.Fatal(err)
	}
	n.Sigs[3].Sig[0] ^= 1 // log-b
	if _, _, err := Open(n.Encode(), va, vb); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("bad known signature: %v", err)
	}
	if _, _, err := Open(n.Encode(), va); err != nil {
		t.Fatalf("a bad unknown signature must be ignored: %v", err)
	}
}

func TestHR194_MLDSA65CoSignature(t *testing.T) {
	origin := "pantherclaw.test/org/0192"
	edS, edV := ed25519Pair(t, origin)
	priv, err := mldsa.GenerateKey(mldsa.MLDSA65())
	if err != nil {
		t.Fatal(err)
	}
	pqS, err := NewMLDSA65Signer(MLDSA65KeyName(origin), priv)
	if err != nil {
		t.Fatal(err)
	}
	pqV, err := NewMLDSA65Verifier(MLDSA65KeyName(origin), priv.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	cp := Checkpoint{Origin: origin, Size: 9, Root: merkle.Hash{1, 2, 3}}
	msg, err := SignCheckpoint(cp, edS, pqS)
	if err != nil {
		t.Fatal(err)
	}
	// A verifier that only knows the Ed25519 key ignores the ML-DSA line.
	got, verified, err := OpenCheckpoint(msg, origin, edV)
	if err != nil || got.Size != 9 || !got.Root.Equal(cp.Root) || len(verified) != 1 {
		t.Fatalf("ed25519 only: %v", err)
	}
	_, verified, err = OpenCheckpoint(msg, origin, edV, pqV)
	if err != nil || !SignedBy(verified, pqV) || !SignedBy(verified, edV) {
		t.Fatalf("both keys: %v", err)
	}
	n, _ := Parse(msg)
	if len(n.Sigs[1].Sig) != mldsa.MLDSA65SignatureSize {
		t.Fatalf("ML-DSA-65 signature is %d bytes", len(n.Sigs[1].Sig))
	}
	n.Sigs[1].Sig[100] ^= 1
	if _, _, err := OpenCheckpoint(n.Encode(), origin, edV, pqV); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("bad ML-DSA signature: %v", err)
	}
	// The context string is part of the signature.
	other, _ := priv.Sign(nil, []byte(n.Text), &mldsa.Options{Context: "other"})
	n.Sigs[1].Sig = other
	if _, _, err := OpenCheckpoint(n.Encode(), origin, pqV); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("ML-DSA signature with another context: %v", err)
	}
	// The key ID binds the PantherClaw type name (0xff ‖ name).
	seeded, err := mldsa.NewPrivateKey(mldsa.MLDSA65(), make([]byte, mldsa.PrivateKeySize))
	if err != nil {
		t.Fatal(err)
	}
	if id := MLDSA65KeyID("example.org/log/ml-dsa-65", seeded.PublicKey()); id != KeyID("example.org/log/ml-dsa-65", append([]byte{0xff}, "pantherclaw.ml-dsa-65.v1"...), seeded.PublicKey().Bytes()) {
		t.Fatalf("ML-DSA key id = %08x", id)
	}
	if _, err := NewMLDSA65Verifier("x", mustMLDSA44(t)); err == nil {
		t.Fatal("ML-DSA-44 key accepted")
	}
}

func mustMLDSA44(t *testing.T) *mldsa.PublicKey {
	t.Helper()
	k, err := mldsa.GenerateKey(mldsa.MLDSA44())
	if err != nil {
		t.Fatal(err)
	}
	return k.PublicKey()
}

func TestParseRejectsMalformedNotes(t *testing.T) {
	good := string(goNote())
	sigLine := emDash + " PeterNeumann " + goSig + "\n"
	many := goText + "\n"
	for i := range MaxSignatures + 1 {
		many += emDash + " k" + strings.Repeat("x", i) + " " + goSig + "\n"
	}
	for name, msg := range map[string]string{
		"no final newline":   strings.TrimSuffix(good, "\n"),
		"no signatures":      goText,
		"no empty line":      goText + sigLine,
		"empty signatures":   goText + "\n\n",
		"control character":  "a\tb\n\n" + sigLine,
		"carriage return":    "ab\r\n\n" + sigLine,
		"invalid utf-8":      "a\xffb\n\n" + sigLine,
		"hyphen not em dash": goText + "\n- PeterNeumann " + goSig + "\n",
		"no key name":        goText + "\n" + emDash + "  " + goSig + "\n",
		"plus in name":       goText + "\n" + emDash + " Peter+Neumann " + goSig + "\n",
		"no signature":       goText + "\n" + emDash + " PeterNeumann\n",
		"short signature":    goText + "\n" + emDash + " PeterNeumann AAAAAA==\n",
		"unpadded base64":    goText + "\n" + emDash + " PeterNeumann " + strings.TrimRight(goSig, "=") + "\n",
		"non-canonical":      goText + "\n" + emDash + " PeterNeumann " + goSig[:len(goSig)-2] + "N=\n",
		"duplicate key":      good + sigLine,
		"too many":           many,
		"too large":          goText + strings.Repeat("x", MaxNoteBytes) + "\n\n" + sigLine,
	} {
		if _, err := Parse([]byte(msg)); !errors.Is(err, ErrMalformed) {
			t.Errorf("%s: err = %v", name, err)
		}
	}
	// A note whose text contains an empty line is valid (the last empty line
	// separates the signatures) and round-trips.
	msg := "a\n\nb\n\n" + sigLine
	n, err := Parse([]byte(msg))
	if err != nil || n.Text != "a\n\nb\n" || string(n.Encode()) != msg {
		t.Fatalf("text with an empty line: %+v %v", n, err)
	}
}

func TestSignRejects(t *testing.T) {
	s, _ := ed25519Pair(t, "k")
	for name, text := range map[string]string{
		"empty":       "",
		"no newline":  "a",
		"empty line":  "a\n\nb\n",
		"leading nl":  "\na\n",
		"control":     "a\x00\n",
		"invalid utf": "\xff\n",
	} {
		if _, err := Sign(text, s); !errors.Is(err, ErrMalformed) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := Sign("a\n"); err == nil {
		t.Error("no signer accepted")
	}
	if _, err := Sign("a\n", s, s); err == nil {
		t.Error("the same key signing twice accepted")
	}
	if _, err := Sign("a\n", fixedSigner{"a b", 1}); err == nil {
		t.Error("key name with a space accepted")
	}
	for _, name := range []string{"", "a b", "a+b", "a\x01", strings.Repeat("n", MaxKeyNameBytes+1)} {
		if _, err := NewEd25519Verifier(name, make([]byte, ed25519.PublicKeySize)); err == nil {
			t.Errorf("key name %q accepted", name)
		}
	}
	if _, err := NewEd25519Verifier("k", make([]byte, 31)); err == nil {
		t.Error("short Ed25519 key accepted")
	}
	if _, err := NewPKIXVerifier("k", []byte("not a key")); err == nil {
		t.Error("garbage PKIX key accepted")
	}
}

func TestCheckpointFormat(t *testing.T) {
	root := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0xab}, 32))
	c, err := ParseCheckpoint("example.com/log\n0\n" + root + "\next one\next two\n")
	if err != nil || c.Size != 0 || len(c.Extensions) != 2 {
		t.Fatalf("parse: %+v %v", c, err)
	}
	text, err := c.Text()
	if err != nil || text != "example.com/log\n0\n"+root+"\next one\next two\n" {
		t.Fatalf("text = %q, %v", text, err)
	}
	for name, text := range map[string]string{
		"two lines":       "o\n1\n",
		"leading zero":    "o\n01\n" + root + "\n",
		"plus sign":       "o\n+1\n" + root + "\n",
		"negative":        "o\n-1\n" + root + "\n",
		"empty size":      "o\n\n" + root + "\n",
		"overflow":        "o\n18446744073709551616\n" + root + "\n",
		"short root":      "o\n1\n" + base64.StdEncoding.EncodeToString(make([]byte, 31)) + "\n",
		"unpadded root":   "o\n1\n" + strings.TrimRight(root, "=") + "\n",
		"empty origin":    "\n1\n" + root + "\n",
		"empty extension": "o\n1\n" + root + "\n\nx\n",
		"long origin":     strings.Repeat("o", MaxOriginBytes+1) + "\n1\n" + root + "\n",
		"many extensions": "o\n1\n" + root + "\n" + strings.Repeat("x\n", MaxExtensionLines+1),
	} {
		if _, err := ParseCheckpoint(text); !errors.Is(err, ErrMalformed) {
			t.Errorf("%s: %v", name, err)
		}
	}
	s, v := ed25519Pair(t, "example.com/log")
	msg, err := SignCheckpoint(Checkpoint{Origin: "example.com/log", Size: 5, Root: merkle.Hash{9}}, s)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := OpenCheckpoint(msg, "example.com/other", v); !errors.Is(err, ErrMalformed) {
		t.Fatalf("wrong origin: %v", err)
	}
	if _, err := SignCheckpoint(Checkpoint{Origin: "o\nx", Size: 1}, s); err == nil {
		t.Fatal("two-line origin accepted")
	}
}

// FuzzSignedNote: parsing never panics, a parsed note re-encodes to exactly
// its input (the encoding is canonical), and a note that opens has a
// signature that verifies over its text.
func FuzzSignedNote(f *testing.F) {
	f.Add(goNote())
	f.Add([]byte(rekorCheckpoint + emDash + rekorSigLine))
	f.Add([]byte("a\n\nb\n\n" + emDash + " k AAAAAAA=\n"))
	f.Add([]byte(goText + "\n" + emDash + " PeterNeumann " + goSig + "\n" + emDash + " other " + goSig + "\n"))
	vk, _ := base64.StdEncoding.DecodeString(goVKey)
	v, err := NewEd25519Verifier("PeterNeumann", vk[1:])
	if err != nil {
		f.Fatal(err)
	}
	f.Fuzz(func(t *testing.T, msg []byte) {
		n, err := Parse(msg)
		if err != nil {
			if !errors.Is(err, ErrMalformed) {
				t.Fatalf("unexpected error type: %v", err)
			}
			return
		}
		if !bytes.Equal(n.Encode(), msg) {
			t.Fatalf("not canonical:\n%q\n%q", msg, n.Encode())
		}
		if len(n.Sigs) == 0 || len(n.Sigs) > MaxSignatures {
			t.Fatalf("%d signatures", len(n.Sigs))
		}
		if _, verified, err := Open(msg, v); err == nil {
			if len(verified) == 0 || !v.Verify([]byte(n.Text), verified[0].Sig) {
				t.Fatal("opened without a verified signature")
			}
		}
		if c, err := ParseCheckpoint(n.Text); err == nil {
			if text, err := c.Text(); err != nil || text != n.Text {
				t.Fatalf("checkpoint not canonical: %q vs %q", text, n.Text)
			}
		}
	})
}
