// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package anchor

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"testing"

	"github.com/katocxl/pantherclaw/internal/evidence/merkle"
	"github.com/katocxl/pantherclaw/internal/evidence/note"
)

const fakeOrigin = "rekor.test/log2026"

// fakeRekor is a local Rekor v2 made from the merkle and note packages and a
// test log key. It checks the request as Rekor does (shape, key details,
// signature over the digest), logs the canonicalized body, signs a
// checkpoint and answers with a TransparencyLogEntry in protojson form.
type fakeRekor struct {
	t       testing.TB
	signer  note.Signer
	tiles   *merkle.MemoryTiles
	mutate  func(f *fakeRekor, resp map[string]any)
	status  int
	raw     []byte // replaces the response body when set
	calls   int
	request []byte
}

func newFakeRekor(t testing.TB, keyType string) (*fakeRekor, Log) {
	t.Helper()
	var (
		signer note.Signer
		der    []byte
		err    error
	)
	switch keyType {
	case "ed25519":
		pub, priv, _ := ed25519.GenerateKey(rand.Reader)
		signer, err = note.NewEd25519Signer(fakeOrigin, priv)
		if err == nil {
			der, err = x509.MarshalPKIXPublicKey(pub)
		}
	case "ecdsa":
		k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		signer, err = note.NewECDSASigner(fakeOrigin, k)
		if err == nil {
			der, err = x509.MarshalPKIXPublicKey(&k.PublicKey)
		}
	}
	if err != nil {
		t.Fatal(err)
	}
	log, err := NewLog(fakeOrigin, der)
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeRekor{t: t, signer: signer, tiles: merkle.NewMemoryTiles(), status: http.StatusCreated}
	// Other entries first, so the anchor's proof crosses a tile boundary.
	for i := range 300 {
		if err := f.tiles.Append(context.Background(), merkle.LeafHash([]byte{byte(i), byte(i >> 8)})); err != nil {
			t.Fatal(err)
		}
	}
	return f, log
}

func b64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

// fakeRequest is the request shape the fake accepts, and nothing else.
type fakeRequest struct {
	Req *struct {
		Digest    []byte `json:"digest"`
		Signature struct {
			Content  []byte `json:"content"`
			Verifier struct {
				PublicKey struct {
					RawBytes []byte `json:"rawBytes"`
				} `json:"publicKey"`
				KeyDetails string `json:"keyDetails"`
			} `json:"verifier"`
		} `json:"signature"`
	} `json:"hashedRekordRequestV002"`
}

// acceptRequest checks a request as Rekor does: the exact shape, the key
// details, and the signature over the digest.
func acceptRequest(body []byte) (fakeRequest, bool) {
	var r fakeRequest
	if json.Unmarshal(body, &r, json.RejectUnknownMembers(true)) != nil || r.Req == nil {
		return r, false
	}
	sig := r.Req.Signature
	pub, err := x509.ParsePKIXPublicKey(sig.Verifier.PublicKey.RawBytes)
	ec, ok := pub.(*ecdsa.PublicKey)
	return r, err == nil && ok && sig.Verifier.KeyDetails == "PKIX_ECDSA_P256_SHA_256" && len(r.Req.Digest) == sha256.Size &&
		ecdsa.VerifyASN1(ec, r.Req.Digest, sig.Content)
}

func reply(status int, body []byte) *http.Response {
	return &http.Response{StatusCode: status, Header: http.Header{"Content-Type": {"application/json"}}, Body: io.NopCloser(bytes.NewReader(body))}
}

func (f *fakeRekor) Do(req *http.Request) (*http.Response, error) {
	f.calls++
	if req.Method != http.MethodPost || req.URL.Path != EntriesPath || req.URL.Host != "rekor.test" ||
		req.Header.Get("Content-Type") != "application/json" {
		return reply(http.StatusBadRequest, nil), nil
	}
	body, _ := io.ReadAll(req.Body)
	f.request = body
	r, ok := acceptRequest(body)
	if !ok {
		return reply(http.StatusBadRequest, nil), nil
	}
	sig := r.Req.Signature
	// The entry as rekor-tiles builds it: protojson, then RFC 8785.
	entry, _ := json.Marshal(map[string]any{
		"apiVersion": "0.0.2", "kind": "hashedrekord",
		"spec": map[string]any{"hashedRekordV002": map[string]any{
			"data": map[string]any{"algorithm": "SHA2_256", "digest": b64(r.Req.Digest)},
			"signature": map[string]any{"content": b64(sig.Content), "verifier": map[string]any{
				"keyDetails": sig.Verifier.KeyDetails, "publicKey": map[string]any{"rawBytes": b64(sig.Verifier.PublicKey.RawBytes)},
			}},
		}},
	})
	canon := jsontext.Value(entry)
	if err := canon.Canonicalize(); err != nil {
		f.t.Fatal(err)
	}
	ctx := context.Background()
	index := f.tiles.Size()
	if err := f.tiles.Append(ctx, merkle.LeafHash(canon)); err != nil {
		f.t.Fatal(err)
	}
	size := f.tiles.Size()
	root, _ := merkle.Root(ctx, f.tiles, size)
	cp, err := note.SignCheckpoint(note.Checkpoint{Origin: fakeOrigin, Size: size, Root: root}, f.signer)
	if err != nil {
		f.t.Fatal(err)
	}
	proof, _ := merkle.InclusionProof(ctx, f.tiles, index, size)
	hashes := []any{}
	for _, h := range proof {
		hashes = append(hashes, b64(h[:]))
	}
	logID := make([]byte, 32)
	binary.BigEndian.PutUint32(logID, f.signer.KeyID())
	resp := map[string]any{
		"logIndex":         strconv.FormatUint(index, 10),
		"logId":            map[string]any{"keyId": b64(logID)},
		"kindVersion":      map[string]any{"kind": "hashedrekord", "version": "0.0.2"},
		"integratedTime":   "0",
		"inclusionPromise": nil,
		"inclusionProof": map[string]any{
			"logIndex": strconv.FormatUint(index, 10), "rootHash": b64(root[:]), "treeSize": strconv.FormatUint(size, 10),
			"hashes": hashes, "checkpoint": map[string]any{"envelope": string(cp)},
		},
		"canonicalizedBody": b64(canon),
	}
	if f.mutate != nil {
		f.mutate(f, resp)
	}
	out, _ := json.Marshal(resp)
	if f.raw != nil {
		out = f.raw
	}
	return reply(f.status, out), nil
}

// proofOf returns the response's inclusion proof member.
func proofOf(resp map[string]any) map[string]any { return resp["inclusionProof"].(map[string]any) }

// resign replaces the response's checkpoint with one for c, signed by s.
func resign(t testing.TB, resp map[string]any, c note.Checkpoint, s note.Signer) {
	t.Helper()
	cp, err := note.SignCheckpoint(c, s)
	if err != nil {
		t.Fatal(err)
	}
	proofOf(resp)["checkpoint"] = map[string]any{"envelope": string(cp)}
}

// checkpointOf parses the response's checkpoint.
func checkpointOf(t testing.TB, resp map[string]any) note.Checkpoint {
	t.Helper()
	env := proofOf(resp)["checkpoint"].(map[string]any)["envelope"].(string)
	n, err := note.Parse([]byte(env))
	if err != nil {
		t.Fatal(err)
	}
	c, err := note.ParseCheckpoint(n.Text)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

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
			c := &RekorClient{URL: "https://rekor.test/", HTTP: fake, Log: log}
			e, raw, err := c.Submit(context.Background(), h)
			if err != nil {
				t.Fatal(err)
			}
			if e.LogIndex != 300 || fake.calls != 1 {
				t.Fatalf("log index %d, %d calls", e.LogIndex, fake.calls)
			}
			want, _ := h.RequestJSON()
			if !bytes.Equal(fake.request, want) {
				t.Fatalf("request = %s", fake.request)
			}
			// The kept entry verifies again offline.
			again, err := ParseEntry(raw)
			if err != nil {
				t.Fatal(err)
			}
			body, _ := h.CanonicalBody()
			cp, err := VerifyEntry(again, log, body)
			if err != nil || cp.Size != 301 || cp.Origin != fakeOrigin {
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
	otherKey, _ := note.NewEd25519Signer(fakeOrigin, otherPriv)
	for name, mutate := range map[string]func(*testing.T, *fakeRekor, map[string]any){
		"proof hash": func(_ *testing.T, _ *fakeRekor, r map[string]any) {
			hs := proofOf(r)["hashes"].([]any)
			b, _ := base64.StdEncoding.DecodeString(hs[0].(string))
			b[0] ^= 1
			hs[0] = b64(b)
		},
		"proof hash dropped": func(_ *testing.T, _ *fakeRekor, r map[string]any) {
			p := proofOf(r)
			p["hashes"] = p["hashes"].([]any)[1:]
		},
		"checkpoint by another key": func(t *testing.T, _ *fakeRekor, r map[string]any) {
			resign(t, r, checkpointOf(t, r), otherKey)
		},
		"checkpoint of another origin": func(t *testing.T, f *fakeRekor, r map[string]any) {
			c := checkpointOf(t, r)
			c.Origin = "rekor.test/other"
			resign(t, r, c, f.signer)
		},
		"checkpoint of another tree": func(t *testing.T, f *fakeRekor, r map[string]any) {
			c := checkpointOf(t, r)
			c.Root[0] ^= 1
			resign(t, r, c, f.signer)
			delete(proofOf(r), "rootHash")
		},
		"checkpoint signature altered": func(t *testing.T, _ *fakeRekor, r map[string]any) {
			cp := proofOf(r)["checkpoint"].(map[string]any)
			cp["envelope"] = strings.Replace(cp["envelope"].(string), "\n301\n", "\n302\n", 1)
		},
		"no checkpoint": func(_ *testing.T, _ *fakeRekor, r map[string]any) { delete(proofOf(r), "checkpoint") },
		"another body": func(_ *testing.T, _ *fakeRekor, r map[string]any) {
			r["canonicalizedBody"] = b64([]byte(`{"apiVersion":"0.0.2","kind":"hashedrekord"}`))
		},
		"another index": func(_ *testing.T, _ *fakeRekor, r map[string]any) {
			r["logIndex"], proofOf(r)["logIndex"] = "299", "299"
		},
		"proof index differs": func(_ *testing.T, _ *fakeRekor, r map[string]any) { proofOf(r)["logIndex"] = "299" },
		"proof tree size":     func(_ *testing.T, _ *fakeRekor, r map[string]any) { proofOf(r)["treeSize"] = "302" },
		"proof root":          func(_ *testing.T, _ *fakeRekor, r map[string]any) { proofOf(r)["rootHash"] = b64(make([]byte, 32)) },
		"kind version": func(_ *testing.T, _ *fakeRekor, r map[string]any) {
			r["kindVersion"] = map[string]any{"kind": "hashedrekord", "version": "0.0.1"}
		},
		"log id": func(_ *testing.T, _ *fakeRekor, r map[string]any) {
			r["logId"] = map[string]any{"keyId": b64([]byte{1, 2, 3, 4})}
		},
		"negative index": func(_ *testing.T, _ *fakeRekor, r map[string]any) {
			r["logIndex"], proofOf(r)["logIndex"] = "-1", "-1"
		},
		"short proof hash": func(_ *testing.T, _ *fakeRekor, r map[string]any) {
			proofOf(r)["hashes"].([]any)[0] = b64([]byte{1})
		},
		"server error":  func(_ *testing.T, f *fakeRekor, _ map[string]any) { f.status = http.StatusInternalServerError },
		"not json":      func(_ *testing.T, f *fakeRekor, _ map[string]any) { f.raw = []byte("<html>") },
		"too large":     func(_ *testing.T, f *fakeRekor, _ map[string]any) { f.raw = bytes.Repeat([]byte(" "), MaxEntryBytes+1) },
		"no proof":      func(_ *testing.T, _ *fakeRekor, r map[string]any) { delete(r, "inclusionProof") },
		"no kind":       func(_ *testing.T, _ *fakeRekor, r map[string]any) { delete(r, "kindVersion") },
		"string number": func(_ *testing.T, _ *fakeRekor, r map[string]any) { r["logIndex"] = "3e2" },
	} {
		t.Run(name, func(t *testing.T) {
			fake, log := newFakeRekor(t, "ed25519")
			fake.mutate = func(f *fakeRekor, r map[string]any) { mutate(t, f, r) }
			c := &RekorClient{URL: "https://rekor.test", HTTP: fake, Log: log}
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
	c := &RekorClient{URL: "https://rekor.test", HTTP: fake, Log: log}
	if _, _, err := c.Submit(context.Background(), bad); !errors.Is(err, ErrInvalidStatement) {
		t.Fatalf("mismatched signature: %v", err)
	}
	if fake.calls != 0 {
		t.Fatalf("%d calls for refused input", fake.calls)
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
	c := &RekorClient{URL: "https://rekor.test", HTTP: fake, Log: log}
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
				if l.Origin != fakeOrigin {
					t.Fatal("the recorded log verified a fabricated entry")
				}
			} else if !errors.Is(err, ErrInvalidEntry) {
				t.Fatalf("error type: %v", err)
			}
		}
	})
}
