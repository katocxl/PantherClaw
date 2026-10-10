// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package note implements C2SP signed notes (c2sp.org/signed-note) and the
// checkpoints written in them (c2sp.org/tlog-checkpoint), for the evidence
// ledger's checkpoints and the transparency log that anchors them (G0 M7
// design decisions 8, 12 and 16, HR-194, PAP-1 §9.4). It uses only the
// standard library.
//
// A signed note is UTF-8 text without control characters other than
// newline, ending in a newline, then an empty line, then one or more
// signature lines
//
//	— <key name> <base64(key ID ‖ signature)>
//
// where the key ID is a big-endian uint32 that, with the key name,
// identifies the verifying key. Verification follows the spec: signatures
// from unknown keys are ignored (a key is known only when both its name and
// its key ID match), a known key's signature that fails rejects the whole
// note, and a note with no verified signature is rejected.
//
// Supported signature types:
//   - Ed25519 (type 0x01): the `checkpoints` key of PantherClaw and Rekor v2
//     logs with Ed25519 keys.
//   - ECDSA P-256 with SHA-256 (type 0x02, as Rekor v2 and the
//     transparency-dev witness implement it): verification of log
//     checkpoints.
//   - ML-DSA-65, PantherClaw's optional post-quantum co-signature on
//     checkpoints (decision 6), under the unregistered type 0xff followed by
//     MLDSA65TypeName.
package note

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Limits for parsing. The spec asks verifiers to accept at least 16
// signatures; one ML-DSA-65 signature line is about 4.5 KB.
const (
	// MaxNoteBytes caps a whole signed note.
	MaxNoteBytes = 64 << 10
	// MaxSignatures caps the signature lines of a note.
	MaxSignatures = 64
	// MaxKeyNameBytes caps a key name.
	MaxKeyNameBytes = 256
)

var (
	// ErrMalformed reports a note that does not follow the format.
	ErrMalformed = errors.New("note: malformed signed note")
	// ErrInvalidSignature reports a signature from a known key that does not
	// verify; the whole note is rejected.
	ErrInvalidSignature = errors.New("note: invalid signature from a known key")
	// ErrUnverified reports a note with no signature from a known key.
	ErrUnverified = errors.New("note: no signature from a known key")
)

// emDash starts every signature line (U+2014).
var emDash = string(rune(0x2014))

// Signature is one signature line.
type Signature struct {
	Name  string // key name
	KeyID uint32 // key ID
	Sig   []byte // algorithm-specific signature, without the key ID
}

// line encodes the signature line, without its final newline.
func (s Signature) line() string {
	b := make([]byte, 4+len(s.Sig))
	binary.BigEndian.PutUint32(b, s.KeyID)
	copy(b[4:], s.Sig)
	return emDash + " " + s.Name + " " + base64.StdEncoding.EncodeToString(b)
}

// Note is a parsed signed note.
type Note struct {
	Text string // the signed text, ending in a newline
	Sigs []Signature
}

// Encode returns the note in its wire form.
func (n *Note) Encode() []byte {
	var b strings.Builder
	b.WriteString(n.Text)
	b.WriteString("\n")
	for _, s := range n.Sigs {
		b.WriteString(s.line())
		b.WriteString("\n")
	}
	return []byte(b.String())
}

// Signer signs note text with one key.
type Signer interface {
	Name() string
	KeyID() uint32
	Sign(msg []byte) ([]byte, error)
}

// Verifier verifies signatures of one key.
type Verifier interface {
	Name() string
	KeyID() uint32
	Verify(msg, sig []byte) bool
}

// KeyID returns the key ID the spec recommends: the first four bytes,
// big-endian, of SHA-256(key name ‖ 0x0A ‖ signature type ‖ public key).
// sigType is one byte, or 0xff followed by a type name.
func KeyID(name string, sigType, pub []byte) uint32 {
	h := sha256.New()
	h.Write([]byte(name))
	h.Write([]byte{'\n'})
	h.Write(sigType)
	h.Write(pub)
	return binary.BigEndian.Uint32(h.Sum(nil))
}

// ValidKeyName reports whether name may name a key: non-empty, at most
// MaxKeyNameBytes, valid UTF-8, no Unicode space and no plus sign.
func ValidKeyName(name string) bool {
	return name != "" && len(name) <= MaxKeyNameBytes && utf8.ValidString(name) &&
		strings.IndexFunc(name, unicode.IsSpace) < 0 && !strings.ContainsRune(name, '+') &&
		strings.IndexFunc(name, isControl) < 0
}

func isControl(r rune) bool { return r < 0x20 || r == 0x7f }

// checkText reports whether text is valid note text: non-empty, valid UTF-8,
// no control characters except newline, ending in a newline.
func checkText(text string) error {
	switch {
	case text == "" || !strings.HasSuffix(text, "\n"):
		return fmt.Errorf("%w: text must end in a newline", ErrMalformed)
	case !utf8.ValidString(text):
		return fmt.Errorf("%w: text is not valid UTF-8", ErrMalformed)
	case strings.IndexFunc(text, func(r rune) bool { return r != '\n' && isControl(r) }) >= 0:
		return fmt.Errorf("%w: text contains a control character", ErrMalformed)
	}
	return nil
}

// Parse decodes a signed note without verifying it. It enforces the format
// and the limits: canonical base64, at most MaxSignatures signatures, no two
// with the same key name and key ID.
func Parse(msg []byte) (*Note, error) {
	if len(msg) > MaxNoteBytes {
		return nil, fmt.Errorf("%w: larger than %d bytes", ErrMalformed, MaxNoteBytes)
	}
	s := string(msg)
	if err := checkText(s); err != nil {
		return nil, err
	}
	split := strings.LastIndex(s, "\n\n")
	if split < 0 {
		return nil, fmt.Errorf("%w: no signatures", ErrMalformed)
	}
	text, sigs := s[:split+1], s[split+2:]
	if sigs == "" {
		return nil, fmt.Errorf("%w: no signatures", ErrMalformed)
	}
	lines := strings.Split(strings.TrimSuffix(sigs, "\n"), "\n")
	if len(lines) > MaxSignatures {
		return nil, fmt.Errorf("%w: more than %d signatures", ErrMalformed, MaxSignatures)
	}
	n := &Note{Text: text}
	for _, l := range lines {
		sig, err := parseLine(l)
		if err != nil {
			return nil, err
		}
		if slices.ContainsFunc(n.Sigs, func(o Signature) bool { return o.Name == sig.Name && o.KeyID == sig.KeyID }) {
			return nil, fmt.Errorf("%w: two signatures from key %s", ErrMalformed, sig.Name)
		}
		n.Sigs = append(n.Sigs, sig)
	}
	return n, nil
}

func parseLine(l string) (Signature, error) {
	rest, ok := strings.CutPrefix(l, emDash+" ")
	if !ok {
		return Signature{}, fmt.Errorf("%w: a signature line must start with an em dash", ErrMalformed)
	}
	name, b64, ok := strings.Cut(rest, " ")
	if !ok || !ValidKeyName(name) {
		return Signature{}, fmt.Errorf("%w: invalid key name in a signature line", ErrMalformed)
	}
	raw, err := decodeBase64(b64)
	if err != nil || len(raw) < 5 {
		return Signature{}, fmt.Errorf("%w: invalid signature encoding for key %s", ErrMalformed, name)
	}
	return Signature{Name: name, KeyID: binary.BigEndian.Uint32(raw), Sig: raw[4:]}, nil
}

// decodeBase64 decodes standard padded base64 and rejects non-canonical
// encodings (RFC 4648 §3.5), as the spec requires.
func decodeBase64(s string) ([]byte, error) {
	b, err := base64.StdEncoding.Strict().DecodeString(s)
	if err != nil || base64.StdEncoding.EncodeToString(b) != s {
		return nil, errors.New("non-canonical base64")
	}
	return b, nil
}

// Sign signs text with each signer and returns the encoded note. The text
// must be valid note text without empty lines.
func Sign(text string, signers ...Signer) ([]byte, error) {
	if err := checkText(text); err != nil {
		return nil, err
	}
	if strings.Contains(text, "\n\n") || strings.HasPrefix(text, "\n") {
		return nil, fmt.Errorf("%w: text must not contain an empty line", ErrMalformed)
	}
	if len(signers) == 0 || len(signers) > MaxSignatures {
		return nil, fmt.Errorf("%w: need 1..%d signers", ErrMalformed, MaxSignatures)
	}
	n := &Note{Text: text}
	for _, s := range signers {
		if !ValidKeyName(s.Name()) {
			return nil, fmt.Errorf("%w: invalid key name %q", ErrMalformed, s.Name())
		}
		if slices.ContainsFunc(n.Sigs, func(o Signature) bool { return o.Name == s.Name() && o.KeyID == s.KeyID() }) {
			return nil, fmt.Errorf("%w: key %s signs twice", ErrMalformed, s.Name())
		}
		sig, err := s.Sign([]byte(text))
		if err != nil {
			return nil, fmt.Errorf("note: sign with %s: %w", s.Name(), err)
		}
		n.Sigs = append(n.Sigs, Signature{Name: s.Name(), KeyID: s.KeyID(), Sig: sig})
	}
	out := n.Encode()
	if len(out) > MaxNoteBytes {
		return nil, fmt.Errorf("%w: larger than %d bytes", ErrMalformed, MaxNoteBytes)
	}
	return out, nil
}

// Open parses msg and verifies it against the known keys. It returns the
// note and the signatures that verified, in note order. A known key is one
// whose name and key ID both match a signature; other signatures are
// ignored. A known key's signature that fails is ErrInvalidSignature, and a
// note without a verified signature is ErrUnverified.
func Open(msg []byte, known ...Verifier) (*Note, []Signature, error) {
	n, err := Parse(msg)
	if err != nil {
		return nil, nil, err
	}
	var verified []Signature
	for _, s := range n.Sigs {
		i := slices.IndexFunc(known, func(v Verifier) bool { return v.Name() == s.Name && v.KeyID() == s.KeyID })
		if i < 0 {
			continue
		}
		if !known[i].Verify([]byte(n.Text), s.Sig) {
			return nil, nil, fmt.Errorf("%w: key %s (%08x)", ErrInvalidSignature, s.Name, s.KeyID)
		}
		verified = append(verified, s)
	}
	if len(verified) == 0 {
		return nil, nil, ErrUnverified
	}
	return n, verified, nil
}

// SignedBy reports whether verified holds a signature from v.
func SignedBy(verified []Signature, v Verifier) bool {
	return slices.ContainsFunc(verified, func(s Signature) bool { return s.Name == v.Name() && s.KeyID == v.KeyID() })
}
