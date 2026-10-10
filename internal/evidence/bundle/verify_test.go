// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package bundle_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/evidence/anchor/anchortest"
	"github.com/katocxl/pantherclaw/internal/evidence/bundle"
	"github.com/katocxl/pantherclaw/internal/evidence/bundle/bundletest"
	"github.com/katocxl/pantherclaw/internal/evidence/note"
)

// scenario is a deployment's evidence: entries 1..11, checkpoints of sizes
// 5 and 9 (co-signed with ML-DSA-65), the checkpoint of size 5 anchored, and
// entries 10 and 11 not in a checkpoint yet.
type scenario struct {
	iss      *bundletest.Issuer
	raw      []byte // the bundle, canonical JSON
	trust    *bundle.Trust
	sigstore *bundle.SigstoreRoot
	saved    []byte // the checkpoint of size 5, saved by the user
}

func newScenario(t testing.TB) *scenario {
	t.Helper()
	iss := bundletest.NewIssuer(t)
	iss.CoSign = true
	iss.Append(5)
	saved := iss.Checkpoint()
	iss.Append(4)
	iss.Checkpoint()
	a := iss.Anchor(5)
	iss.Append(2)
	b := iss.Bundle()
	b.Anchor = a
	trust, err := bundle.ParseTrust(iss.Trust())
	if err != nil {
		t.Fatal(err)
	}
	sig, err := bundle.ParseSigstoreRoot(iss.SigstoreRoot())
	if err != nil {
		t.Fatal(err)
	}
	return &scenario{iss: iss, raw: bundletest.Encode(t, b), trust: trust, sigstore: sig, saved: saved}
}

func (s *scenario) bundle(t testing.TB) *bundle.Bundle {
	t.Helper()
	b, err := bundle.Decode(s.raw)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func (s *scenario) verify(t testing.TB, b *bundle.Bundle) *bundle.Report {
	t.Helper()
	return bundle.Verify(b, bundle.Options{Trust: s.trust, Sigstore: s.sigstore, Previous: s.saved})
}

// statuses returns the statuses of the checks named name, in order.
func statuses(r *bundle.Report, name string) []bundle.Status {
	var out []bundle.Status
	for _, c := range r.Checks {
		if c.Name == name {
			out = append(out, c.Status)
		}
	}
	return out
}

func count(r *bundle.Report, name string, s bundle.Status) int {
	n := 0
	for _, st := range statuses(r, name) {
		if st == s {
			n++
		}
	}
	return n
}

func expect(t *testing.T, r *bundle.Report, name string, want ...bundle.Status) {
	t.Helper()
	got := statuses(r, name)
	if len(got) != len(want) {
		t.Fatalf("%s: %v, want %v\n%s", name, got, want, r.Text())
	}
	for i := range got {
		if got[i] != want[i] {
			t.Fatalf("%s: %v, want %v\n%s", name, got, want, r.Text())
		}
	}
}

func repeat(s bundle.Status, n int) []bundle.Status {
	out := make([]bundle.Status, n)
	for i := range out {
		out[i] = s
	}
	return out
}

// TestHR196_GoodBundlePassesOffline: every signature, link, proof, anchor
// and timestamp of a good bundle passes, with nothing but the pinned keys
// and files (Verify takes no client and does no I/O).
func TestHR196_GoodBundlePassesOffline(t *testing.T) {
	s := newScenario(t)
	r := s.verify(t, s.bundle(t))
	if r.Failed() || r.Result != bundle.Passed {
		t.Fatalf("good bundle failed:\n%s", r.Text())
	}
	p, na := bundle.Passed, bundle.NotAvailable
	expect(t, r, "bundle.origin", p)
	expect(t, r, "checkpoint.signature", p, p)
	expect(t, r, "checkpoint.cosignature", p, p)
	expect(t, r, "checkpoint.consistency", p)
	expect(t, r, "witness.previous", p)
	expect(t, r, "entry.link", repeat(p, 11)...)
	expect(t, r, "entry.inclusion", append(repeat(p, 9), na, na)...)
	expect(t, r, "receipt.signature", repeat(p, 11)...)
	expect(t, r, "receipt.ledger", repeat(p, 11)...)
	expect(t, r, "anchor.leaf", p)
	expect(t, r, "anchor.signature", p)
	expect(t, r, "anchor.root", p)
	expect(t, r, "anchor.log", p)
	expect(t, r, "anchor.timestamp", p)
	if !strings.HasSuffix(strings.TrimSpace(r.Text()), bundle.Limits) || r.Limits != bundle.Limits {
		t.Fatal("the report does not end with the limits")
	}
	if !strings.Contains(r.Text(), "the anchor existed by 2026-10-10T09:00:05Z") {
		t.Fatalf("the timestamp is not reported:\n%s", r.Text())
	}
	// The canonical encoding round-trips.
	again, err := bundle.Encode(s.bundle(t))
	if err != nil || !bytes.Equal(again, s.raw) {
		t.Fatalf("encode: %v", err)
	}
}

func flip(b []byte) []byte {
	c := bytes.Clone(b)
	c[len(c)/2] ^= 1
	return c
}

// flipJWS changes one character of a compact JWS's payload.
func flipJWS(s string) string {
	parts := strings.Split(s, ".")
	p := []byte(parts[1])
	if p[3] == 'A' {
		p[3] = 'B'
	} else {
		p[3] = 'A'
	}
	parts[1] = string(p)
	return strings.Join(parts, ".")
}

// TestHR196_ModifiedEvidenceFails: a modified receipt, entry, proof,
// checkpoint, anchor or timestamp fails its check.
func TestHR196_ModifiedEvidenceFails(t *testing.T) {
	_, otherKey, _ := ed25519.GenerateKey(rand.Reader)
	for name, tc := range map[string]struct {
		mutate func(*testing.T, *scenario, *bundle.Bundle)
		check  string
	}{
		"receipt payload": {func(_ *testing.T, _ *scenario, b *bundle.Bundle) { b.Receipts[2] = flipJWS(b.Receipts[2]) }, "receipt.signature"},
		"receipt signature": {func(_ *testing.T, _ *scenario, b *bundle.Bundle) {
			r := []byte(b.Receipts[0])
			r[len(r)-3] ^= 1
			b.Receipts[0] = string(r)
		}, "receipt.signature"},
		"entry body": {func(_ *testing.T, _ *scenario, b *bundle.Bundle) {
			b.Entries[3].Body = jsontext.Value(bytes.Replace(b.Entries[3].Body, []byte("ALLOW"), []byte("DENY!"), 1))
		}, "entry.link"},
		"entry kind": {func(_ *testing.T, _ *scenario, b *bundle.Bundle) { b.Entries[3].Kind = "authz.other" }, "entry.link"},
		"entry time": {func(_ *testing.T, _ *scenario, b *bundle.Bundle) { b.Entries[3].TS = "2026-10-10T08:30:04.000001Z" }, "entry.link"},
		"entry hash": {func(_ *testing.T, _ *scenario, b *bundle.Bundle) {
			b.Entries[3].EntryHash = flip(b.Entries[3].EntryHash)
		}, "entry.link"},
		"entry hash, last": {func(_ *testing.T, _ *scenario, b *bundle.Bundle) {
			b.Entries[8].EntryHash = flip(b.Entries[8].EntryHash)
		}, "entry.inclusion"},
		"prev hash": {func(_ *testing.T, _ *scenario, b *bundle.Bundle) { b.Entries[4].PrevHash = flip(b.Entries[4].PrevHash) }, "entry.link"},
		"inclusion proof": {func(_ *testing.T, _ *scenario, b *bundle.Bundle) {
			b.Inclusion[2].Proof[0] = flip(b.Inclusion[2].Proof[0])
		}, "entry.inclusion"},
		"inclusion dropped": {func(_ *testing.T, _ *scenario, b *bundle.Bundle) {
			b.Inclusion = b.Inclusion[1:]
		}, "entry.inclusion"},
		"consistency proof": {func(_ *testing.T, _ *scenario, b *bundle.Bundle) {
			b.Consistency[0].Proof[0] = flip(b.Consistency[0].Proof[0])
		}, "checkpoint.consistency"},
		"consistency dropped": {func(_ *testing.T, _ *scenario, b *bundle.Bundle) { b.Consistency = nil }, "checkpoint.consistency"},
		"checkpoint root": {func(_ *testing.T, _ *scenario, b *bundle.Bundle) {
			b.Checkpoints[1] = strings.Replace(b.Checkpoints[1], "\n9\n", "\n8\n", 1)
		}, "checkpoint.signature"},
		"checkpoint by another key": {func(t *testing.T, s *scenario, b *bundle.Bundle) {
			n, _ := note.Parse([]byte(b.Checkpoints[1]))
			signer, _ := note.NewEd25519Signer(s.iss.Origin, otherKey)
			resigned, err := note.Sign(n.Text, signer)
			if err != nil {
				t.Fatal(err)
			}
			b.Checkpoints[1] = string(resigned)
		}, "checkpoint.signature"},
		"ML-DSA co-signature": {func(t *testing.T, _ *scenario, b *bundle.Bundle) {
			n, _ := note.Parse([]byte(b.Checkpoints[0]))
			n.Sigs[1].Sig[10] ^= 1
			b.Checkpoints[0] = string(n.Encode())
		}, "checkpoint.cosignature"},
		"anchor nonce":     {func(_ *testing.T, _ *scenario, b *bundle.Bundle) { b.Anchor.Nonce = flip(b.Anchor.Nonce) }, "anchor.leaf"},
		"anchor leaves":    {func(_ *testing.T, _ *scenario, b *bundle.Bundle) { b.Anchor.Leaves = b.Anchor.Leaves[:3] }, "anchor.root"},
		"anchor statement": {func(_ *testing.T, _ *scenario, b *bundle.Bundle) { b.Anchor.Statement = flip(b.Anchor.Statement) }, "anchor.signature"},
		"anchor signature": {func(_ *testing.T, _ *scenario, b *bundle.Bundle) { b.Anchor.Signature = flip(b.Anchor.Signature) }, "anchor.signature"},
		"anchor checkpoint": {func(_ *testing.T, _ *scenario, b *bundle.Bundle) {
			b.Anchor.Checkpoint = 9
		}, "anchor.leaf"},
		"rekor entry": {func(_ *testing.T, _ *scenario, b *bundle.Bundle) {
			b.Anchor.RekorEntry = jsontext.Value(strings.Replace(string(b.Anchor.RekorEntry), `"logIndex":"300"`, `"logIndex":"299"`, 2))
		}, "anchor.log"},
		"rekor checkpoint": {func(_ *testing.T, _ *scenario, b *bundle.Bundle) {
			b.Anchor.RekorEntry = jsontext.Value(strings.Replace(string(b.Anchor.RekorEntry), `\n301\n`, `\n302\n`, 1))
		}, "anchor.log"},
		"timestamp": {func(_ *testing.T, _ *scenario, b *bundle.Bundle) {
			b.Anchor.Timestamp[len(b.Anchor.Timestamp)-5] ^= 1
		}, "anchor.timestamp"},
		"timestamp of another anchor": {func(t *testing.T, s *scenario, b *bundle.Bundle) {
			b.Anchor.Timestamp = s.iss.Anchor(5).Timestamp
		}, "anchor.timestamp"},
	} {
		t.Run(name, func(t *testing.T) {
			s := newScenario(t)
			b := s.bundle(t)
			tc.mutate(t, s, b)
			r := s.verify(t, b)
			if !r.Failed() || count(r, tc.check, bundle.Failed) == 0 {
				t.Fatalf("%s did not fail:\n%s", tc.check, r.Text())
			}
			for _, c := range r.Checks {
				if c.Status == bundle.Failed {
					t.Logf("%s [%s]: %s", c.Name, c.Subject, c.Detail)
				}
			}
		})
	}
}

// TestHR196_RemovedBodyAndMissingAnchorAreNotAvailable: a body removed by
// retention and a bundle without an anchor or Sigstore root are reported as
// not available, never as passed or failed, and the rest still verifies.
func TestHR196_RemovedBodyAndMissingAnchorAreNotAvailable(t *testing.T) {
	s := newScenario(t)
	b := s.bundle(t)
	b.Entries[2].Body = nil
	b.Entries[2].Removed = &bundle.Removal{At: "2027-10-10T00:00:00Z", Policy: "receipts r2"}
	b.Anchor = nil
	r := bundle.Verify(b, bundle.Options{Trust: s.trust})
	if r.Failed() {
		t.Fatalf("failed:\n%s", r.Text())
	}
	p, na := bundle.Passed, bundle.NotAvailable
	expect(t, r, "entry.link", p, p, na, p, p, p, p, p, p, p, p)
	expect(t, r, "entry.inclusion", append(repeat(p, 9), na, na)...)
	expect(t, r, "receipt.ledger", append(append(repeat(p, 2), na), repeat(p, 8)...)...)
	expect(t, r, "anchor", na)
	expect(t, r, "witness.previous", na)
	if !strings.Contains(r.Text(), "body removed by retention policy receipts r2 on 2027-10-10T00:00:00Z") {
		t.Fatalf("the removal is not reported:\n%s", r.Text())
	}
	// With an anchor but no Sigstore root, its log and timestamp are not
	// available.
	r = bundle.Verify(s.bundle(t), bundle.Options{Trust: s.trust})
	expect(t, r, "anchor.log", na)
	expect(t, r, "anchor.timestamp", na)
	expect(t, r, "anchor.signature", p)
}

// trustWithout returns the scenario's trust file without the keys of a
// purpose, or with them changed.
func trustWith(t *testing.T, s *scenario, change func(*bundle.TrustedKey) bool) *bundle.Trust {
	t.Helper()
	var keep []bundle.TrustedKey
	for _, k := range s.trust.Keys {
		if change(&k) {
			keep = append(keep, k)
		}
	}
	raw, err := json.Marshal(bundle.Trust{Format: bundle.TrustFormat, LogOrigin: s.trust.LogOrigin, Keys: keep})
	if err != nil {
		t.Fatal(err)
	}
	tr, err := bundle.ParseTrust(raw)
	if err != nil {
		t.Fatal(err)
	}
	return tr
}

// TestHR196_KeysNotInTheTrustFileFail: evidence signed by keys the user did
// not pin, revoked keys, keys outside their validity and another
// deployment's trust file fail.
func TestHR196_KeysNotInTheTrustFileFail(t *testing.T) {
	s := newScenario(t)
	for name, tc := range map[string]struct {
		change func(*bundle.TrustedKey) bool
		checks []string
	}{
		"no receipts key":    {func(k *bundle.TrustedKey) bool { return k.Purpose != bundle.PurposeReceipts }, []string{"receipt.signature"}},
		"no checkpoints key": {func(k *bundle.TrustedKey) bool { return k.Purpose != bundle.PurposeCheckpoints }, []string{"checkpoint.signature"}},
		"no anchors key":     {func(k *bundle.TrustedKey) bool { return k.Purpose != bundle.PurposeAnchors }, []string{"anchor.signature"}},
		"revoked receipts key": {func(k *bundle.TrustedKey) bool {
			if k.Purpose == bundle.PurposeReceipts {
				k.State = bundle.StateRevoked
			}
			return true
		}, []string{"receipt.signature"}},
		"receipts key not yet valid": {func(k *bundle.TrustedKey) bool {
			if k.Purpose == bundle.PurposeReceipts {
				k.NotBefore = bundletest.IssuedAt.Add(time.Hour)
			}
			return true
		}, []string{"receipt.signature"}},
		"receipts key expired": {func(k *bundle.TrustedKey) bool {
			if k.Purpose == bundle.PurposeReceipts {
				k.NotAfter = bundletest.IssuedAt.Add(-time.Hour)
			}
			return true
		}, []string{"receipt.signature"}},
		"revoked checkpoints key": {func(k *bundle.TrustedKey) bool {
			if k.Purpose == bundle.PurposeCheckpoints {
				k.State = bundle.StateRevoked
			}
			return true
		}, []string{"checkpoint.signature", "witness.previous"}},
		"anchors key expired before the timestamp": {func(k *bundle.TrustedKey) bool {
			if k.Purpose == bundle.PurposeAnchors {
				k.NotAfter = anchortest.TSANow.Add(-time.Minute)
			}
			return true
		}, []string{"anchor.timestamp"}},
	} {
		t.Run(name, func(t *testing.T) {
			tr := trustWith(t, s, tc.change)
			r := bundle.Verify(s.bundle(t), bundle.Options{Trust: tr, Sigstore: s.sigstore, Previous: s.saved})
			for _, c := range tc.checks {
				if count(r, c, bundle.Failed) == 0 {
					t.Fatalf("%s did not fail:\n%s", c, r.Text())
				}
			}
		})
	}
	// Another deployment's trust file: nothing it signed counts.
	other := bundletest.NewIssuer(t)
	tr, err := bundle.ParseTrust(other.Trust())
	if err != nil {
		t.Fatal(err)
	}
	r := bundle.Verify(s.bundle(t), bundle.Options{Trust: tr, Sigstore: s.sigstore})
	if count(r, "receipt.signature", bundle.Passed)+count(r, "checkpoint.signature", bundle.Passed)+count(r, "anchor.signature", bundle.Passed) != 0 {
		t.Fatalf("another deployment's keys verified something:\n%s", r.Text())
	}
	// A trust file for another log origin fails the origin.
	wrong := *s.trust
	wrong.LogOrigin = "evidence.other"
	if r := bundle.Verify(s.bundle(t), bundle.Options{Trust: &wrong}); count(r, "bundle.origin", bundle.Failed) != 1 {
		t.Fatalf("origin:\n%s", r.Text())
	}
	// A Sigstore root of other logs and authorities fails the anchor's.
	otherRoot, err := bundle.ParseSigstoreRoot(other.SigstoreRoot())
	if err != nil {
		t.Fatal(err)
	}
	r = bundle.Verify(s.bundle(t), bundle.Options{Trust: s.trust, Sigstore: otherRoot})
	expect(t, r, "anchor.log", bundle.Failed)
	expect(t, r, "anchor.timestamp", bundle.Failed)
}

// TestHR196_ResignedHistoryWithoutWitnessIsDetected is the BUILD_GUIDE
// "re-signing without a witness" test: an insider rewrites entry 3 and
// re-signs the rewritten tree with the real checkpoints key. On its own the
// rewritten bundle verifies (a signature proves who signed, not that
// nothing was rewritten); against a checkpoint the user saved earlier, or
// against the anchored root, the rewrite is detected.
func TestHR196_ResignedHistoryWithoutWitnessIsDetected(t *testing.T) {
	honest := bundletest.NewIssuer(t)
	honest.Append(6)
	saved := honest.Checkpoint()
	anchored := honest.Anchor(6)
	honest.Append(4)
	honest.Checkpoint()
	trust, err := bundle.ParseTrust(honest.Trust())
	if err != nil {
		t.Fatal(err)
	}
	sig, err := bundle.ParseSigstoreRoot(honest.SigstoreRoot())
	if err != nil {
		t.Fatal(err)
	}

	forged := honest.Rewrite(3)
	forged.Checkpoint() // size 10, signed with the real key
	fb := forged.Bundle()

	// No witness: the rewrite passes. This is what witnesses are for.
	r := bundle.Verify(fb, bundle.Options{Trust: trust, Sigstore: sig})
	if r.Failed() || count(r, "witness.previous", bundle.NotAvailable) != 1 || count(r, "anchor", bundle.NotAvailable) != 1 {
		t.Fatalf("expected the rewrite to pass without a witness:\n%s", r.Text())
	}

	// --previous: the saved checkpoint of size 6 is not extended by the
	// rewritten tree, with or without the forger's own proof.
	r = bundle.Verify(fb, bundle.Options{Trust: trust, Sigstore: sig, Previous: saved})
	expect(t, r, "witness.previous", bundle.Failed)
	fb.Consistency = append(fb.Consistency, forged.Consistency(6, 10))
	r = bundle.Verify(fb, bundle.Options{Trust: trust, Sigstore: sig, Previous: saved})
	expect(t, r, "witness.previous", bundle.Failed)

	// The anchored root: the anchor commits to the real checkpoint of size
	// 6, which the rewritten checkpoint of size 10 does not extend.
	withAnchor := forged.Bundle()
	withAnchor.Anchor = anchored
	withAnchor.Checkpoints = append([]string{string(saved)}, withAnchor.Checkpoints...)
	withAnchor.Consistency = append(withAnchor.Consistency, forged.Consistency(6, 10))
	r = bundle.Verify(withAnchor, bundle.Options{Trust: trust, Sigstore: sig})
	expect(t, r, "anchor.leaf", bundle.Passed)
	expect(t, r, "anchor.log", bundle.Passed)
	expect(t, r, "checkpoint.consistency", bundle.Failed)
	// Leaving the real checkpoint out breaks the anchor instead.
	withAnchor.Checkpoints = withAnchor.Checkpoints[1:]
	r = bundle.Verify(withAnchor, bundle.Options{Trust: trust, Sigstore: sig})
	expect(t, r, "anchor.leaf", bundle.Failed)
	// Re-signing a rewritten checkpoint of size 6 as well shows two
	// different signed trees of the same size.
	forged.CheckpointAt(6)
	forged6 := forged.Bundle()
	forged6.Checkpoints = append(forged6.Checkpoints, string(saved))
	r = bundle.Verify(forged6, bundle.Options{Trust: trust})
	if count(r, "checkpoint.signature", bundle.Failed) != 1 || !strings.Contains(r.Text(), "forked history") {
		t.Fatalf("split view not detected:\n%s", r.Text())
	}
}

func TestDecodeIsStrict(t *testing.T) {
	s := newScenario(t)
	good := string(s.raw)
	for name, doc := range map[string]string{
		"unknown member":   strings.Replace(good, `{"anchor":`, `{"extra":1,"anchor":`, 1),
		"duplicate member": strings.Replace(good, `"format":`, `"format":"x","format":`, 1),
		"format":           strings.Replace(good, bundle.Format, "pantherclaw.bundle/v2", 1),
		"short hash":       strings.Replace(good, `"entry_hash":"`, `"entry_hash":"AAAA","x":"`, 1),
		"not json":         "{",
		"too large":        good + strings.Repeat(" ", bundle.MaxBundleBytes),
	} {
		if _, err := bundle.Decode([]byte(doc)); !errors.Is(err, bundle.ErrInvalidBundle) {
			t.Errorf("%s: %v", name, err)
		}
	}
	for name, mutate := range map[string]func(*bundle.Bundle){
		"order":            func(b *bundle.Bundle) { b.Entries[1], b.Entries[2] = b.Entries[2], b.Entries[1] },
		"body and removal": func(b *bundle.Bundle) { b.Entries[0].Removed = &bundle.Removal{At: "x", Policy: "y"} },
		"no body":          func(b *bundle.Bundle) { b.Entries[0].Body = nil },
		"bad nonce":        func(b *bundle.Bundle) { b.Anchor.Nonce = b.Anchor.Nonce[:5] },
		"zero seq":         func(b *bundle.Bundle) { b.Entries[0].Seq = 0 },
	} {
		b := s.bundle(t)
		mutate(b)
		if _, err := bundle.Encode(b); !errors.Is(err, bundle.ErrInvalidBundle) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestTrustFileIsStrict(t *testing.T) {
	s := newScenario(t)
	good := string(s.iss.Trust())
	for name, doc := range map[string]string{
		"unknown member":    strings.Replace(good, `"format"`, `"x":1,"format"`, 1),
		"wrong algorithm":   strings.Replace(good, `"algorithm":"ES256"`, `"algorithm":"EdDSA"`, 1),
		"unknown purpose":   strings.Replace(good, `"purpose":"receipts"`, `"purpose":"permits"`, 1),
		"unknown state":     strings.Replace(good, `"state":"ACTIVE"`, `"state":"active"`, 1),
		"no origin":         strings.Replace(good, `"log_origin":"evidence.test"`, `"log_origin":""`, 1),
		"repeated kid":      strings.Replace(good, `"kid":"checkpoints-test-1"`, `"kid":"anchors-test-1"`, 1),
		"format":            strings.Replace(good, bundle.TrustFormat, "pantherclaw.trust/v2", 1),
		"short EdDSA key":   strings.Replace(good, `"public_key":"`, `"public_key":"AAAA","x":"`, 1),
		"validity reversed": strings.Replace(good, `"not_before":"2026-09-10T08:30:00Z"`, `"not_before":"2026-09-10T08:30:00Z","not_after":"2026-01-01T00:00:00Z"`, 1),
	} {
		if _, err := bundle.ParseTrust([]byte(doc)); !errors.Is(err, bundle.ErrInvalidTrust) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := bundle.ParseSigstoreRoot([]byte(`{"mediaType":"application/json"}`)); !errors.Is(err, bundle.ErrInvalidSigstoreRoot) {
		t.Errorf("media type: %v", err)
	}
	if _, err := bundle.ParseSigstoreRoot([]byte(`{"mediaType":"application/vnd.dev.sigstore.trustedroot+json;version=0.1"}`)); !errors.Is(err, bundle.ErrInvalidSigstoreRoot) {
		t.Errorf("empty root: %v", err)
	}
}

// FuzzBundle: any input decodes to a bundle or ErrInvalidBundle, and
// verifying what decodes never panics and never passes a check for evidence
// the trust file does not cover.
func FuzzBundle(f *testing.F) {
	s := newScenario(f)
	f.Add(s.raw)
	f.Add([]byte(`{"format":"pantherclaw.bundle/v1","org":"x","origin":"y"}`))
	f.Add([]byte(`{"format":"pantherclaw.bundle/v1","org":"x","origin":"y","entries":[{"seq":1}]}`))
	opts := bundle.Options{Trust: s.trust, Sigstore: s.sigstore, Previous: s.saved}
	other := bundletest.NewIssuer(f)
	otherTrust, err := bundle.ParseTrust(other.Trust())
	if err != nil {
		f.Fatal(err)
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		b, err := bundle.Decode(raw)
		if err != nil {
			if !errors.Is(err, bundle.ErrInvalidBundle) {
				t.Fatalf("error type: %v", err)
			}
			return
		}
		_ = bundle.Verify(b, opts)
		r := bundle.Verify(b, bundle.Options{Trust: otherTrust})
		for _, c := range r.Checks {
			if c.Status == bundle.Passed && strings.HasSuffix(c.Name, "signature") {
				t.Fatalf("%s passed with an unrelated trust file", c.Name)
			}
		}
	})
}
