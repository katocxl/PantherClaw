// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package anchor

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/katocxl/pantherclaw/internal/evidence/merkle"
	"github.com/katocxl/pantherclaw/internal/evidence/note"
)

// Rekor v2 (github.com/sigstore/rekor-tiles): one write API,
// POST /api/v2/log/entries, taking a hashedrekord v0.0.2 request and
// returning a TransparencyLogEntry (sigstore protobuf-specs, protojson). The
// entry carries the log's signed checkpoint and the inclusion proof of the
// canonicalized body; Rekor v2 issues no timestamps (integrated time is 0).
const (
	// KeyDetailsECDSAP256 is the protobuf-specs PublicKeyDetails of the
	// anchors key.
	KeyDetailsECDSAP256 = "PKIX_ECDSA_P256_SHA_256"
	// EntriesPath is Rekor v2's write API.
	EntriesPath = "/api/v2/log/entries"
	// MaxEntryBytes caps a Rekor response.
	MaxEntryBytes = 1 << 20
	// maxProofHashes caps an inclusion proof (a tree of at most 2^63 leaves).
	maxProofHashes = 63
)

// ErrInvalidEntry reports a Rekor entry that is malformed or does not
// verify.
var ErrInvalidEntry = errors.New("anchor: invalid transparency log entry")

// Doer sends HTTP requests. The anchoring job passes the M1 egress client
// (HR-070..072); tests pass local fakes.
type Doer interface {
	Do(*http.Request) (*http.Response, error)
}

// Log identifies a Rekor v2 log: the origin its checkpoints carry (the
// scheme-less log URL) and the key that signs them.
type Log struct {
	Origin   string
	Verifier note.Verifier
}

// NewLog returns the log of origin with its public key in PKIX DER
// (Ed25519 or ECDSA P-256), as Sigstore's trusted_root.json lists it.
func NewLog(origin string, publicKey []byte) (Log, error) {
	v, err := note.NewPKIXVerifier(origin, publicKey)
	if err != nil {
		return Log{}, err
	}
	return Log{Origin: origin, Verifier: v}, nil
}

// HashedRekord is the entry an anchor makes: the SHA-256 digest of the
// canonical statement, the anchors key's signature over it and that key.
type HashedRekord struct {
	Digest    [sha256.Size]byte
	Signature []byte // ECDSA P-256 SHA-256, ASN.1 DER
	PublicKey []byte // PKIX DER of the anchors key
}

// FromSigned returns the hashedrekord of a signed statement.
func FromSigned(s Signed, publicKey []byte) HashedRekord {
	return HashedRekord{Digest: s.Digest, Signature: s.Signature, PublicKey: publicKey}
}

func (h HashedRekord) check() error {
	pub, err := ParseAnchorKey(h.PublicKey)
	if err != nil {
		return err
	}
	if !ecdsa.VerifyASN1(pub, h.Digest[:], h.Signature) {
		return fmt.Errorf("%w: the signature does not verify", ErrInvalidStatement)
	}
	return nil
}

type rekorPublicKey struct {
	RawBytes []byte `json:"rawBytes"`
}

type rekorVerifier struct {
	PublicKey  rekorPublicKey `json:"publicKey"`
	KeyDetails string         `json:"keyDetails"`
}

type rekorSignature struct {
	Content  []byte        `json:"content"`
	Verifier rekorVerifier `json:"verifier"`
}

// RequestJSON returns the body of POST /api/v2/log/entries.
func (h HashedRekord) RequestJSON() ([]byte, error) {
	if err := h.check(); err != nil {
		return nil, err
	}
	type request struct {
		Digest    []byte         `json:"digest"`
		Signature rekorSignature `json:"signature"`
	}
	type createEntryRequest struct {
		Req request `json:"hashedRekordRequestV002"`
	}
	return json.Marshal(createEntryRequest{request{h.Digest[:], h.signature()}})
}

func (h HashedRekord) signature() rekorSignature {
	return rekorSignature{Content: h.Signature, Verifier: rekorVerifier{
		PublicKey: rekorPublicKey{RawBytes: h.PublicKey}, KeyDetails: KeyDetailsECDSAP256,
	}}
}

// CanonicalBody returns the log entry Rekor v2 stores for h: the RFC 8785
// form of
//
//	{"apiVersion":"0.0.2","kind":"hashedrekord","spec":{"hashedRekordV002":
//	  {"data":{"algorithm":"SHA2_256","digest":…},"signature":{…}}}}
//
// Its RFC 9162 leaf hash is what the log's inclusion proof proves. The
// verifier rebuilds it from the anchor rather than trusting the body the
// log returned.
func (h HashedRekord) CanonicalBody() ([]byte, error) {
	if err := h.check(); err != nil {
		return nil, err
	}
	type data struct {
		Algorithm string `json:"algorithm"`
		Digest    []byte `json:"digest"`
	}
	type entry struct {
		Data      data           `json:"data"`
		Signature rekorSignature `json:"signature"`
	}
	type spec struct {
		Entry entry `json:"hashedRekordV002"`
	}
	type logEntry struct {
		APIVersion string `json:"apiVersion"`
		Kind       string `json:"kind"`
		Spec       spec   `json:"spec"`
	}
	b, err := json.Marshal(logEntry{"0.0.2", "hashedrekord", spec{entry{data{"SHA2_256", h.Digest[:]}, h.signature()}}})
	if err != nil {
		return nil, err
	}
	v := jsontext.Value(b)
	if err := v.Canonicalize(); err != nil {
		return nil, err
	}
	return v, nil
}

// pbInt64 is a protojson int64: a decimal string, or a number.
type pbInt64 int64

// UnmarshalJSON accepts "123" and 123.
func (n *pbInt64) UnmarshalJSON(b []byte) error {
	s := string(b)
	if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
		s = s[1 : len(s)-1]
	}
	v, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return fmt.Errorf("invalid int64 %q", truncate(s))
	}
	*n = pbInt64(v)
	return nil
}

// MarshalJSON writes the protojson form, a decimal string.
func (n pbInt64) MarshalJSON() ([]byte, error) {
	return []byte(`"` + strconv.FormatInt(int64(n), 10) + `"`), nil
}

// Entry is a TransparencyLogEntry (dev.sigstore.rekor.v1) in its protojson
// form. Unknown members are ignored, as protojson readers do.
type Entry struct {
	LogIndex pbInt64 `json:"logIndex"`
	LogID    *struct {
		KeyID []byte `json:"keyId"`
	} `json:"logId,omitempty"`
	KindVersion *struct {
		Kind    string `json:"kind"`
		Version string `json:"version"`
	} `json:"kindVersion"`
	IntegratedTime pbInt64         `json:"integratedTime"`
	InclusionProof *InclusionProof `json:"inclusionProof"`
	// CanonicalizedBody is the log entry; it must equal the one rebuilt
	// from the anchor.
	CanonicalizedBody []byte `json:"canonicalizedBody,omitempty"`
}

// InclusionProof is the entry's proof and the log checkpoint it leads to.
type InclusionProof struct {
	LogIndex   pbInt64  `json:"logIndex"`
	RootHash   []byte   `json:"rootHash,omitempty"`
	TreeSize   pbInt64  `json:"treeSize"`
	Hashes     [][]byte `json:"hashes"`
	Checkpoint *struct {
		Envelope string `json:"envelope"`
	} `json:"checkpoint"`
}

// ParseEntry decodes a TransparencyLogEntry.
func ParseEntry(b []byte) (*Entry, error) {
	if len(b) > MaxEntryBytes {
		return nil, fmt.Errorf("%w: larger than %d bytes", ErrInvalidEntry, MaxEntryBytes)
	}
	var e Entry
	if err := json.Unmarshal(b, &e); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidEntry, err)
	}
	switch p := e.InclusionProof; {
	case e.KindVersion == nil || p == nil || p.Checkpoint == nil:
		return nil, fmt.Errorf("%w: kind, inclusion proof and checkpoint are required", ErrInvalidEntry)
	case e.LogIndex < 0 || p.LogIndex < 0 || p.TreeSize < 0:
		return nil, fmt.Errorf("%w: negative index or size", ErrInvalidEntry)
	case len(p.Hashes) > maxProofHashes:
		return nil, fmt.Errorf("%w: inclusion proof too long", ErrInvalidEntry)
	}
	for _, h := range e.InclusionProof.Hashes {
		if len(h) != merkle.HashSize {
			return nil, fmt.Errorf("%w: proof hash is not 32 bytes", ErrInvalidEntry)
		}
	}
	return &e, nil
}

// VerifyEntry checks that e records body in log: the kind is hashedrekord
// 0.0.2, the returned body (when present) equals body, the checkpoint is
// signed by the log's key and carries its origin, and the inclusion proof
// of body's leaf hash at the entry's index leads to the checkpoint's root.
// The duplicated proof fields and the log id, when present, must agree. It
// returns the verified log checkpoint.
func VerifyEntry(e *Entry, log Log, body []byte) (note.Checkpoint, error) {
	if e == nil || e.KindVersion == nil || e.InclusionProof == nil || e.InclusionProof.Checkpoint == nil {
		return note.Checkpoint{}, fmt.Errorf("%w: incomplete entry", ErrInvalidEntry)
	}
	if e.KindVersion.Kind != "hashedrekord" || e.KindVersion.Version != "0.0.2" {
		return note.Checkpoint{}, fmt.Errorf("%w: kind %q version %q is not hashedrekord 0.0.2",
			ErrInvalidEntry, truncate(e.KindVersion.Kind), truncate(e.KindVersion.Version))
	}
	if len(e.CanonicalizedBody) > 0 && !bytes.Equal(e.CanonicalizedBody, body) {
		return note.Checkpoint{}, fmt.Errorf("%w: the log recorded a different entry", ErrInvalidEntry)
	}
	cp, _, err := note.OpenCheckpoint([]byte(e.InclusionProof.Checkpoint.Envelope), log.Origin, log.Verifier)
	if err != nil {
		return note.Checkpoint{}, fmt.Errorf("%w: log checkpoint: %w", ErrInvalidEntry, err)
	}
	p := e.InclusionProof
	switch {
	case e.LogIndex < 0 || p.LogIndex != e.LogIndex:
		return note.Checkpoint{}, fmt.Errorf("%w: inconsistent log index", ErrInvalidEntry)
	case p.TreeSize < 0:
		return note.Checkpoint{}, fmt.Errorf("%w: negative tree size", ErrInvalidEntry)
	case p.TreeSize != 0 && uint64(p.TreeSize) != cp.Size:
		return note.Checkpoint{}, fmt.Errorf("%w: proof tree size differs from the checkpoint", ErrInvalidEntry)
	case len(p.RootHash) > 0 && !bytes.Equal(p.RootHash, cp.Root[:]):
		return note.Checkpoint{}, fmt.Errorf("%w: proof root differs from the checkpoint", ErrInvalidEntry)
	case e.LogID != nil && len(e.LogID.KeyID) > 0 &&
		(len(e.LogID.KeyID) < 4 || binary.BigEndian.Uint32(e.LogID.KeyID) != log.Verifier.KeyID()):
		return note.Checkpoint{}, fmt.Errorf("%w: log id does not match the log key", ErrInvalidEntry)
	}
	hashes := make([]merkle.Hash, len(p.Hashes))
	for i, h := range p.Hashes {
		if hashes[i], err = merkle.HashFromBytes(h); err != nil {
			return note.Checkpoint{}, fmt.Errorf("%w: %w", ErrInvalidEntry, err)
		}
	}
	if err := merkle.VerifyInclusion(merkle.LeafHash(body), uint64(e.LogIndex), cp.Size, hashes, cp.Root); err != nil {
		return note.Checkpoint{}, fmt.Errorf("%w: %w", ErrInvalidEntry, err)
	}
	return cp, nil
}

// RekorClient enters anchors in a Rekor v2 log.
type RekorClient struct {
	URL  string // the log's base URL, https
	HTTP Doer
	Log  Log
}

// Submit enters h, verifies the returned entry against the log's key and
// origin, and returns the entry with its raw JSON (kept with the anchor).
// The anchor counts only if this succeeds (HR-195). Rekor v2 answers once a
// checkpoint covers the entry, so callers allow at least 20 seconds.
func (c *RekorClient) Submit(ctx context.Context, h HashedRekord) (*Entry, []byte, error) {
	reqBody, err := h.RequestJSON()
	if err != nil {
		return nil, nil, err
	}
	body, err := h.CanonicalBody()
	if err != nil {
		return nil, nil, err
	}
	endpoint, err := endpointURL(c.URL, EntriesPath)
	if err != nil {
		return nil, nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(reqBody))
	if err != nil {
		return nil, nil, fmt.Errorf("anchor: rekor request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	raw, err := send(c.HTTP, req, MaxEntryBytes, http.StatusOK, http.StatusCreated)
	if err != nil {
		return nil, nil, fmt.Errorf("anchor: rekor: %w", err)
	}
	e, err := ParseEntry(raw)
	if err != nil {
		return nil, nil, err
	}
	if _, err := VerifyEntry(e, c.Log, body); err != nil {
		return nil, nil, err
	}
	return e, raw, nil
}

// endpointURL joins an https base URL and a path.
func endpointURL(base, path string) (string, error) {
	u, err := url.Parse(base)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.RawQuery != "" || u.Fragment != "" || u.User != nil {
		return "", fmt.Errorf("anchor: %q is not an https base URL", truncate(base))
	}
	return strings.TrimSuffix(u.String(), "/") + path, nil
}

// send performs req and returns at most limit bytes of a response with one
// of the accepted statuses. Response bodies never reach errors or logs.
func send(d Doer, req *http.Request, limit int64, accept ...int) ([]byte, error) {
	if d == nil {
		return nil, errors.New("no HTTP client")
	}
	resp, err := d.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	ok := false
	for _, s := range accept {
		ok = ok || resp.StatusCode == s
	}
	if !ok {
		return nil, fmt.Errorf("HTTP status %d", resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > limit {
		return nil, fmt.Errorf("response larger than %d bytes", limit)
	}
	return b, nil
}

func truncate(s string) string {
	if len(s) > 64 {
		return s[:64] + "…"
	}
	return s
}
