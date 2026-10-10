// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package anchor

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/katocxl/pantherclaw/internal/evidence/anchor/anchortest"
	"github.com/katocxl/pantherclaw/internal/evidence/merkle"
	"github.com/katocxl/pantherclaw/internal/evidence/note"
)

// newFakeRekor returns a local Rekor v2 log (anchortest) and its Log.
func newFakeRekor(t testing.TB, keyType string) (*anchortest.Rekor, Log) {
	t.Helper()
	r := anchortest.NewRekor(t, keyType)
	log, err := NewLog(anchortest.RekorOrigin, r.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return r, log
}

func b64(b []byte) string { return anchortest.B64(b) }

func signedAnchor(t testing.TB) HashedRekord {
	t.Helper()
	key, pub := anchorsKey(t)
	s, err := SignStatement(key, Statement{Origin: "evidence.test/anchors", Period: testPeriod, Size: 4, Root: merkle.Hash{3}})
	if err != nil {
		t.Fatal(err)
	}
	return FromSigned(s, pub)
}

func TestHR195_RekorRequestIsWellFormedAndEntryVerifies(t *testing.T) {
	for _, keyType := range []string{"ed25519", "ecdsa"} {
		t.Run(keyType, func(t *testing.T) {
			fake, log := newFakeRekor(t, keyType)
			h := signedAnchor(t)
			c := &RekorClient{URL: anchortest.RekorURL + "/", HTTP: fake, Log: log}
			e, raw, err := c.Submit(context.Background(), h)
			if err != nil {
				t.Fatal(err)
			}
			if e.LogIndex != 300 || fake.Calls != 1 {
				t.Fatalf("log index %d, %d calls", e.LogIndex, fake.Calls)
			}
			want, _ := h.RequestJSON()
			if !bytes.Equal(fake.Request, want) {
				t.Fatalf("request = %s", fake.Request)
			}
			// The kept entry verifies again offline.
			again, err := ParseEntry(raw)
			if err != nil {
				t.Fatal(err)
			}
			body, _ := h.CanonicalBody()
			cp, err := VerifyEntry(again, log, body)
			if err != nil || cp.Size != 301 || cp.Origin != anchortest.RekorOrigin {
				t.Fatalf("offline: %+v %v", cp, err)
			}
			// The entry proves only this anchor.
			other := signedAnchor(t)
			otherBody, _ := other.CanonicalBody()
			if _, err := VerifyEntry(again, log, otherBody); !errors.Is(err, ErrInvalidEntry) {
				t.Fatalf("another anchor's body verified: %v", err)
			}
		})
	}
}

// TestHR195_BadRekorEntryIsRejected: an entry whose proof, checkpoint, body,
// index, size, kind or log id does not verify never counts.
func TestHR195_BadRekorEntryIsRejected(t *testing.T) {
	_, otherPriv, _ := ed25519.GenerateKey(rand.Reader)
	otherKey, _ := note.NewEd25519Signer(anchortest.RekorOrigin, otherPriv)
	for name, mutate := range map[string]func(*testing.T, *anchortest.Rekor, map[string]any){
		"proof hash": func(_ *testing.T, _ *anchortest.Rekor, r map[string]any) {
			hs := anchortest.ProofOf(r)["hashes"].([]any)
			b, _ := base64.StdEncoding.DecodeString(hs[0].(string))
			b[0] ^= 1
			hs[0] = b64(b)
		},
		"proof hash dropped": func(_ *testing.T, _ *anchortest.Rekor, r map[string]any) {
			p := anchortest.ProofOf(r)
			p["hashes"] = p["hashes"].([]any)[1:]
		},
		"checkpoint by another key": func(t *testing.T, _ *anchortest.Rekor, r map[string]any) {
			anchortest.Resign(t, r, anchortest.CheckpointOf(t, r), otherKey)
		},
		"checkpoint of another origin": func(t *testing.T, f *anchortest.Rekor, r map[string]any) {
			c := anchortest.CheckpointOf(t, r)
			c.Origin = "rekor.test/other"
			anchortest.Resign(t, r, c, f.Signer)
		},
		"checkpoint of another tree": func(t *testing.T, f *anchortest.Rekor, r map[string]any) {
			c := anchortest.CheckpointOf(t, r)
			c.Root[0] ^= 1
			anchortest.Resign(t, r, c, f.Signer)
			delete(anchortest.ProofOf(r), "rootHash")
		},
		"checkpoint signature altered": func(t *testing.T, _ *anchortest.Rekor, r map[string]any) {
			cp := anchortest.ProofOf(r)["checkpoint"].(map[string]any)
			cp["envelope"] = strings.Replace(cp["envelope"].(string), "\n301\n", "\n302\n", 1)
		},
		"no checkpoint": func(_ *testing.T, _ *anchortest.Rekor, r map[string]any) { delete(anchortest.ProofOf(r), "checkpoint") },
		"another body": func(_ *testing.T, _ *anchortest.Rekor, r map[string]any) {
			r["canonicalizedBody"] = b64([]byte(`{"apiVersion":"0.0.2","kind":"hashedrekord"}`))
		},
		"another index": func(_ *testing.T, _ *anchortest.Rekor, r map[string]any) {
			r["logIndex"], anchortest.ProofOf(r)["logIndex"] = "299", "299"
		},
		"proof index differs": func(_ *testing.T, _ *anchortest.Rekor, r map[string]any) { anchortest.ProofOf(r)["logIndex"] = "299" },
		"proof tree size":     func(_ *testing.T, _ *anchortest.Rekor, r map[string]any) { anchortest.ProofOf(r)["treeSize"] = "302" },
		"proof root": func(_ *testing.T, _ *anchortest.Rekor, r map[string]any) {
			anchortest.ProofOf(r)["rootHash"] = b64(make([]byte, 32))
		},
		"kind version": func(_ *testing.T, _ *anchortest.Rekor, r map[string]any) {
			r["kindVersion"] = map[string]any{"kind": "hashedrekord", "version": "0.0.1"}
		},
		"log id": func(_ *testing.T, _ *anchortest.Rekor, r map[string]any) {
			r["logId"] = map[string]any{"keyId": b64([]byte{1, 2, 3, 4})}
		},
		"negative index": func(_ *testing.T, _ *anchortest.Rekor, r map[string]any) {
			r["logIndex"], anchortest.ProofOf(r)["logIndex"] = "-1", "-1"
		},
		"short proof hash": func(_ *testing.T, _ *anchortest.Rekor, r map[string]any) {
			anchortest.ProofOf(r)["hashes"].([]any)[0] = b64([]byte{1})
		},
		"server error": func(_ *testing.T, f *anchortest.Rekor, _ map[string]any) { f.Status = http.StatusInternalServerError },
		"not json":     func(_ *testing.T, f *anchortest.Rekor, _ map[string]any) { f.Raw = []byte("<html>") },
		"too large": func(_ *testing.T, f *anchortest.Rekor, _ map[string]any) {
			f.Raw = bytes.Repeat([]byte(" "), MaxEntryBytes+1)
		},
		"no proof":      func(_ *testing.T, _ *anchortest.Rekor, r map[string]any) { delete(r, "inclusionProof") },
		"no kind":       func(_ *testing.T, _ *anchortest.Rekor, r map[string]any) { delete(r, "kindVersion") },
		"string number": func(_ *testing.T, _ *anchortest.Rekor, r map[string]any) { r["logIndex"] = "3e2" },
	} {
		t.Run(name, func(t *testing.T) {
			fake, log := newFakeRekor(t, "ed25519")
			fake.Mutate = func(f *anchortest.Rekor, r map[string]any) { mutate(t, f, r) }
			c := &RekorClient{URL: anchortest.RekorURL, HTTP: fake, Log: log}
			_, _, err := c.Submit(context.Background(), signedAnchor(t))
			if err == nil {
				t.Fatal("a bad entry was accepted")
			}
			t.Log(err)
		})
	}
}

func TestRekorClientRefusesBadInput(t *testing.T) {
	fake, log := newFakeRekor(t, "ed25519")
	h := signedAnchor(t)
	for name, c := range map[string]*RekorClient{
		"http":      {URL: "http://rekor.test", HTTP: fake, Log: log},
		"query":     {URL: "https://rekor.test?x=1", HTTP: fake, Log: log},
		"userinfo":  {URL: "https://u:p@rekor.test", HTTP: fake, Log: log},
		"no client": {URL: "https://rekor.test", Log: log},
	} {
		if _, _, err := c.Submit(context.Background(), h); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	bad := h
	bad.Digest[0] ^= 1 // the signature no longer matches
	c := &RekorClient{URL: anchortest.RekorURL, HTTP: fake, Log: log}
	if _, _, err := c.Submit(context.Background(), bad); !errors.Is(err, ErrInvalidStatement) {
		t.Fatalf("mismatched signature: %v", err)
	}
	if fake.Calls != 0 {
		t.Fatalf("%d calls for refused input", fake.Calls)
	}
}

// TestHR195_RekorRecordedEntryVerifies checks the verifier against entries
// recorded from Sigstore's Rekor v2 staging log, and the canonical body
// against the one that log stored.
func TestHR195_RekorRecordedEntryVerifies(t *testing.T) {
	log := recordedLog(t)
	for _, name := range recordedCases {
		t.Run(name, func(t *testing.T) {
			b := recordedBundleFor(t, name)
			e, err := ParseEntry(b.VerificationMaterial.TlogEntries[0])
			if err != nil {
				t.Fatal(err)
			}
			cp, err := VerifyEntry(e, log, e.CanonicalizedBody)
			if err != nil {
				t.Fatal(err)
			}
			if cp.Origin != "log2025-alpha1.rekor.sigstage.dev" || cp.Size <= uint64(e.LogIndex) {
				t.Fatalf("checkpoint %+v", cp)
			}
			changed := bytes.Clone(e.CanonicalizedBody)
			changed[len(changed)-3] ^= 1
			if _, err := VerifyEntry(e, log, changed); !errors.Is(err, ErrInvalidEntry) {
				t.Fatalf("changed body: %v", err)
			}
			e.CanonicalizedBody = nil // rely on the rebuilt body alone
			if _, err := VerifyEntry(e, log, changed); !errors.Is(err, ErrInvalidEntry) {
				t.Fatalf("changed body without the logged copy: %v", err)
			}

			// Our canonical body is byte-for-byte what Rekor v2 stores, with the
			// public key verifier in place of the certificate.
			cert, err := x509.ParseCertificate(b.VerificationMaterial.Certificate.RawBytes)
			if err != nil {
				t.Fatal(err)
			}
			var digest [32]byte
			copy(digest[:], b.MessageSignature.MessageDigest.Digest)
			h := HashedRekord{Digest: digest, Signature: b.MessageSignature.Signature, PublicKey: cert.RawSubjectPublicKeyInfo}
			got, err := h.CanonicalBody()
			if err != nil {
				t.Fatal(err)
			}
			raw, _ := ParseEntry(b.VerificationMaterial.TlogEntries[0])
			want := strings.Replace(string(raw.CanonicalizedBody),
				`"x509Certificate":{"rawBytes":"`+b64(cert.Raw)+`"}`, `"publicKey":{"rawBytes":"`+b64(cert.RawSubjectPublicKeyInfo)+`"}`, 1)
			if string(got) != want {
				t.Fatalf("canonical body:\n got %s\nwant %s", got, want)
			}
		})
	}
	// Another origin or key never verifies the recorded entry.
	b := recordedBundleFor(t, recordedCases[0])
	e, _ := ParseEntry(b.VerificationMaterial.TlogEntries[0])
	_, other := newFakeRekor(t, "ecdsa")
	if _, err := VerifyEntry(e, other, e.CanonicalizedBody); !errors.Is(err, ErrInvalidEntry) {
		t.Fatalf("other log: %v", err)
	}
}

// FuzzRekorEntry: parsing and verifying arbitrary responses never panics,
// fails only with ErrInvalidEntry, and never accepts an entry whose
// checkpoint is not signed by the log.
func FuzzRekorEntry(f *testing.F) {
	b := recordedBundleFor(f, recordedCases[0])
	f.Add([]byte(b.VerificationMaterial.TlogEntries[0]))
	fake, log := newFakeRekor(f, "ed25519")
	c := &RekorClient{URL: anchortest.RekorURL, HTTP: fake, Log: log}
	h := signedAnchor(f)
	if _, raw, err := c.Submit(context.Background(), h); err == nil {
		f.Add(raw)
	}
	f.Add([]byte(`{"logIndex":1,"kindVersion":{"kind":"hashedrekord","version":"0.0.2"},"inclusionProof":{"logIndex":"1","treeSize":"2","hashes":[],"checkpoint":{"envelope":"x\n2\nAAAA\n\n"}}}`))
	body, _ := h.CanonicalBody()
	recorded := recordedLog(f)
	f.Fuzz(func(t *testing.T, raw []byte) {
		e, err := ParseEntry(raw)
		if err != nil {
			if !errors.Is(err, ErrInvalidEntry) {
				t.Fatalf("error type: %v", err)
			}
			return
		}
		for _, l := range []Log{log, recorded} {
			if _, err := VerifyEntry(e, l, body); err == nil {
				// Only an entry the fake log really signed for this body can pass.
				if l.Origin != anchortest.RekorOrigin {
					t.Fatal("the recorded log verified a fabricated entry")
				}
			} else if !errors.Is(err, ErrInvalidEntry) {
				t.Fatalf("error type: %v", err)
			}
		}
	})
}
