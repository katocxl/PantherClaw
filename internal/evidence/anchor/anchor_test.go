// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package anchor

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/evidence/merkle"
)

var testPeriod = time.Date(2026, 10, 10, 9, 0, 0, 0, time.UTC)

func anchorsKey(t testing.TB) (*ecdsa.PrivateKey, []byte) {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&k.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return k, der
}

func TestHR195_StatementIsCanonicalJSON(t *testing.T) {
	s := Statement{Origin: "evidence.example.com/anchors", Period: testPeriod.Add(30 * time.Minute).In(time.FixedZone("x", 3600)), Size: 3, Root: merkle.Hash{1}}
	c, err := s.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	want := `{"origin":"evidence.example.com/anchors","period":"2026-10-10T09:30:00Z","root":"AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",` +
		`"size":3,"type":"pantherclaw.anchor","v":1}`
	if string(c) != want {
		t.Fatalf("statement:\n got %s\nwant %s", c, want)
	}
	got, err := ParseStatement(c)
	if err != nil || got.Origin != s.Origin || !got.Period.Equal(s.Period) || got.Size != 3 || !got.Root.Equal(s.Root) {
		t.Fatalf("parse: %+v %v", got, err)
	}
	for name, b := range map[string]string{
		"whitespace":     strings.Replace(want, `,"size"`, `, "size"`, 1),
		"member order":   `{"v":1,"type":"pantherclaw.anchor","origin":"evidence.example.com/anchors","period":"2026-10-10T09:30:00Z","size":3,"root":"AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}`,
		"unknown member": strings.Replace(want, `"v":1}`, `"v":1,"x":1}`, 1),
		"duplicate":      strings.Replace(want, `"v":1}`, `"v":1,"v":1}`, 1),
		"version":        strings.Replace(want, `"v":1}`, `"v":2}`, 1),
		"type":           strings.Replace(want, `"pantherclaw.anchor"`, `"other"`, 1),
		"zero size":      strings.Replace(want, `"size":3`, `"size":0`, 1),
		"short root":     strings.Replace(want, `AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=`, `AQAA`, 1),
		"local time":     strings.Replace(want, `09:30:00Z`, `10:30:00+01:00`, 1),
		"too large":      want + strings.Repeat(" ", MaxStatementBytes),
	} {
		if _, err := ParseStatement([]byte(b)); !errors.Is(err, ErrInvalidStatement) {
			t.Errorf("%s: %v", name, err)
		}
	}
	for name, s := range map[string]Statement{
		"no origin": {Period: testPeriod, Size: 1},
		"no period": {Origin: "o", Size: 1},
		"no size":   {Origin: "o", Period: testPeriod},
		"too large": {Origin: "o", Period: testPeriod, Size: 1<<53 + 1},
	} {
		if _, err := s.Canonical(); !errors.Is(err, ErrInvalidStatement) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestHR195_StatementSignature(t *testing.T) {
	key, pub := anchorsKey(t)
	s := Statement{Origin: "o", Period: testPeriod, Size: 2, Root: merkle.Hash{7}}
	signed, err := SignStatement(key, s)
	if err != nil {
		t.Fatal(err)
	}
	if signed.Digest != sha256.Sum256(signed.Statement) {
		t.Fatal("digest is not SHA-256 of the statement")
	}
	if _, err := VerifyStatement(pub, signed.Statement, signed.Signature); err != nil {
		t.Fatal(err)
	}
	_, otherPub := anchorsKey(t)
	if _, err := VerifyStatement(otherPub, signed.Statement, signed.Signature); !errors.Is(err, ErrInvalidStatement) {
		t.Fatalf("another key: %v", err)
	}
	changed := bytes.Replace(signed.Statement, []byte(`"size":2`), []byte(`"size":3`), 1)
	if _, err := VerifyStatement(pub, changed, signed.Signature); !errors.Is(err, ErrInvalidStatement) {
		t.Fatalf("changed statement: %v", err)
	}
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if _, err := SignStatement(p384, s); err == nil {
		t.Fatal("a P-384 anchors key was accepted")
	}
}

// TestHR195_LeavesChangeEveryAnchorAndRevealNoOrg: a quiet org (same
// checkpoint) gets a different leaf in every anchor, two orgs with the same
// note cannot be linked, and the tree orders leaves by value, not by org.
func TestHR195_LeavesChangeEveryAnchorAndRevealNoOrg(t *testing.T) {
	checkpoint := []byte("evidence.example.com/org/0192\n5\nAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n\n— evidence.example.com/org/0192 AAAAAQ==\n")
	seen := map[merkle.Hash]bool{}
	for range 64 {
		n, err := NewNonce()
		if err != nil {
			t.Fatal(err)
		}
		l := Leaf(n, checkpoint)
		if seen[l] {
			t.Fatal("a quiet org's leaf repeated")
		}
		seen[l] = true
	}
	// The leaf is the RFC 9162 leaf hash of domain ‖ nonce ‖ SHA-256(note).
	var n Nonce
	n[0] = 9
	d := sha256.Sum256(checkpoint)
	want := merkle.LeafHash(append(append([]byte(LeafDomain), n[:]...), d[:]...))
	if got := Leaf(n, checkpoint); !got.Equal(want) {
		t.Fatalf("leaf = %x, want %x", got, want)
	}
	// The leaf of an org depends only on its nonce and note: no org id, and
	// without the nonce it cannot be recomputed from the note.
	if Leaf(Nonce{}, checkpoint).Equal(Leaf(Nonce{1}, checkpoint)) {
		t.Fatal("the nonce does not blind the leaf")
	}

	var leaves []merkle.Hash
	for range 5 {
		nn, _ := NewNonce()
		leaves = append(leaves, Leaf(nn, checkpoint))
	}
	tree, err := NewTree(leaves)
	if err != nil {
		t.Fatal(err)
	}
	ordered := tree.Leaves()
	for i := 1; i < len(ordered); i++ {
		if bytes.Compare(ordered[i-1][:], ordered[i][:]) >= 0 {
			t.Fatal("leaves are not ordered by value")
		}
	}
	for _, l := range leaves {
		i, proof, err := tree.InclusionProof(l)
		if err != nil {
			t.Fatal(err)
		}
		if err := merkle.VerifyInclusion(l, i, tree.Size(), proof, tree.Root()); err != nil {
			t.Fatal(err)
		}
	}
	again, err := TreeFromOrderedLeaves(ordered)
	if err != nil || !again.Root().Equal(tree.Root()) {
		t.Fatalf("rebuilt tree: %v", err)
	}
	if _, err := TreeFromOrderedLeaves(leaves); err == nil && !equalOrder(leaves, ordered) {
		t.Fatal("unordered leaves accepted")
	}
	if _, err := NewTree(append(leaves, leaves[0])); !errors.Is(err, ErrInvalidTree) {
		t.Fatal("duplicate leaf accepted")
	}
	if _, err := NewTree(nil); !errors.Is(err, ErrInvalidTree) {
		t.Fatal("empty tree accepted")
	}
	if _, _, err := tree.InclusionProof(merkle.Hash{1}); !errors.Is(err, ErrInvalidTree) {
		t.Fatal("proof for a leaf outside the tree")
	}
}

func equalOrder(a, b []merkle.Hash) bool {
	for i := range a {
		if !a[i].Equal(b[i]) {
			return false
		}
	}
	return true
}
