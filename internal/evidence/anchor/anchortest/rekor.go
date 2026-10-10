// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package anchortest provides local fakes of a Rekor v2 log and an RFC 3161
// timestamp authority, for tests of the anchor clients and of offline
// verification. They never touch the network: they implement the anchor
// package's Doer. It does not import package anchor, so that package's own
// tests can use it, and its encoders are independent of the verifiers they
// test.
package anchortest

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
	"io"
	"net/http"
	"strconv"
	"testing"

	"github.com/katocxl/pantherclaw/internal/evidence/merkle"
	"github.com/katocxl/pantherclaw/internal/evidence/note"
)

// RekorOrigin is the fake log's origin (its checkpoint key name).
const RekorOrigin = "rekor.test/log2026"

// RekorURL is the base URL the fake log answers on.
const RekorURL = "https://rekor.test"

// Rekor is a local Rekor v2 log made from the merkle and note packages and
// a test log key. It checks requests as Rekor does (exact shape, key
// details, signature over the digest), logs the canonicalized body, signs a
// checkpoint and answers with a TransparencyLogEntry in protojson form.
type Rekor struct {
	T         testing.TB
	Signer    note.Signer
	PublicKey []byte // PKIX DER of the log key
	Tiles     *merkle.MemoryTiles
	// Mutate changes the response before it is sent.
	Mutate func(r *Rekor, resp map[string]any)
	// Status is the HTTP status of answers (201 by default).
	Status int
	// Raw replaces the response body when set.
	Raw []byte
	// Calls counts requests; Request is the last request body.
	Calls   int
	Request []byte
}

// NewRekor returns a fake log with an "ed25519" or "ecdsa" (P-256) key that
// already holds 300 other entries, so proofs cross a tile boundary.
func NewRekor(t testing.TB, keyType string) *Rekor {
	t.Helper()
	var (
		signer note.Signer
		der    []byte
		err    error
	)
	switch keyType {
	case "ed25519":
		pub, priv, _ := ed25519.GenerateKey(rand.Reader)
		signer, err = note.NewEd25519Signer(RekorOrigin, priv)
		if err == nil {
			der, err = x509.MarshalPKIXPublicKey(pub)
		}
	case "ecdsa":
		k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		signer, err = note.NewECDSASigner(RekorOrigin, k)
		if err == nil {
			der, err = x509.MarshalPKIXPublicKey(&k.PublicKey)
		}
	default:
		t.Fatalf("anchortest: unknown key type %q", keyType)
	}
	if err != nil {
		t.Fatal(err)
	}
	r := &Rekor{T: t, Signer: signer, PublicKey: der, Tiles: merkle.NewMemoryTiles(), Status: http.StatusCreated}
	for i := range 300 {
		if err := r.Tiles.Append(context.Background(), merkle.LeafHash([]byte{byte(i), byte(i >> 8)})); err != nil {
			t.Fatal(err)
		}
	}
	return r
}

// B64 is standard padded base64, as protojson writes bytes.
func B64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

type request struct {
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
func acceptRequest(body []byte) (request, bool) {
	var r request
	if json.Unmarshal(body, &r, json.RejectUnknownMembers(true)) != nil || r.Req == nil {
		return r, false
	}
	sig := r.Req.Signature
	pub, err := x509.ParsePKIXPublicKey(sig.Verifier.PublicKey.RawBytes)
	ec, ok := pub.(*ecdsa.PublicKey)
	return r, err == nil && ok && sig.Verifier.KeyDetails == "PKIX_ECDSA_P256_SHA_256" && len(r.Req.Digest) == sha256.Size &&
		ecdsa.VerifyASN1(ec, r.Req.Digest, sig.Content)
}

// Reply returns an HTTP response with a body.
func Reply(status int, body []byte) *http.Response {
	return &http.Response{StatusCode: status, Header: http.Header{"Content-Type": {"application/json"}}, Body: io.NopCloser(bytes.NewReader(body))}
}

// Do implements the anchor package's Doer.
func (r *Rekor) Do(req *http.Request) (*http.Response, error) {
	r.Calls++
	if req.Method != http.MethodPost || req.URL.Path != "/api/v2/log/entries" || req.URL.Host != "rekor.test" ||
		req.Header.Get("Content-Type") != "application/json" {
		return Reply(http.StatusBadRequest, nil), nil
	}
	body, _ := io.ReadAll(req.Body)
	r.Request = body
	in, ok := acceptRequest(body)
	if !ok {
		return Reply(http.StatusBadRequest, nil), nil
	}
	sig := in.Req.Signature
	// The entry as rekor-tiles builds it: protojson, then RFC 8785.
	entry, _ := json.Marshal(map[string]any{
		"apiVersion": "0.0.2", "kind": "hashedrekord",
		"spec": map[string]any{"hashedRekordV002": map[string]any{
			"data": map[string]any{"algorithm": "SHA2_256", "digest": B64(in.Req.Digest)},
			"signature": map[string]any{"content": B64(sig.Content), "verifier": map[string]any{
				"keyDetails": sig.Verifier.KeyDetails, "publicKey": map[string]any{"rawBytes": B64(sig.Verifier.PublicKey.RawBytes)},
			}},
		}},
	})
	canon := jsontext.Value(entry)
	if err := canon.Canonicalize(); err != nil {
		r.T.Fatal(err)
	}
	ctx := context.Background()
	index := r.Tiles.Size()
	if err := r.Tiles.Append(ctx, merkle.LeafHash(canon)); err != nil {
		r.T.Fatal(err)
	}
	size := r.Tiles.Size()
	root, _ := merkle.Root(ctx, r.Tiles, size)
	cp, err := note.SignCheckpoint(note.Checkpoint{Origin: RekorOrigin, Size: size, Root: root}, r.Signer)
	if err != nil {
		r.T.Fatal(err)
	}
	proof, _ := merkle.InclusionProof(ctx, r.Tiles, index, size)
	hashes := []any{}
	for _, h := range proof {
		hashes = append(hashes, B64(h[:]))
	}
	logID := make([]byte, 32)
	binary.BigEndian.PutUint32(logID, r.Signer.KeyID())
	resp := map[string]any{
		"logIndex":         strconv.FormatUint(index, 10),
		"logId":            map[string]any{"keyId": B64(logID)},
		"kindVersion":      map[string]any{"kind": "hashedrekord", "version": "0.0.2"},
		"integratedTime":   "0",
		"inclusionPromise": nil,
		"inclusionProof": map[string]any{
			"logIndex": strconv.FormatUint(index, 10), "rootHash": B64(root[:]), "treeSize": strconv.FormatUint(size, 10),
			"hashes": hashes, "checkpoint": map[string]any{"envelope": string(cp)},
		},
		"canonicalizedBody": B64(canon),
	}
	if r.Mutate != nil {
		r.Mutate(r, resp)
	}
	out, _ := json.Marshal(resp)
	if r.Raw != nil {
		out = r.Raw
	}
	return Reply(r.Status, out), nil
}

// ProofOf returns a response's inclusion proof member.
func ProofOf(resp map[string]any) map[string]any {
	p, _ := resp["inclusionProof"].(map[string]any)
	return p
}

// Resign replaces a response's checkpoint with one for c signed by s.
func Resign(t testing.TB, resp map[string]any, c note.Checkpoint, s note.Signer) {
	t.Helper()
	cp, err := note.SignCheckpoint(c, s)
	if err != nil {
		t.Fatal(err)
	}
	ProofOf(resp)["checkpoint"] = map[string]any{"envelope": string(cp)}
}

// CheckpointOf parses a response's checkpoint.
func CheckpointOf(t testing.TB, resp map[string]any) note.Checkpoint {
	t.Helper()
	cp, _ := ProofOf(resp)["checkpoint"].(map[string]any)
	env, _ := cp["envelope"].(string)
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
