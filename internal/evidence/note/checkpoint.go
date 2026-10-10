// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package note

import (
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"

	"github.com/katocxl/pantherclaw/internal/evidence/merkle"
)

// Checkpoint limits.
const (
	// MaxOriginBytes caps a checkpoint origin.
	MaxOriginBytes = 256
	// MaxExtensionLines caps the extension lines of a checkpoint.
	MaxExtensionLines = 16
)

// Checkpoint is the body of a checkpoint note (c2sp.org/tlog-checkpoint):
//
//	<origin>
//	<tree size, decimal>
//	<root hash, base64>
//	[extension lines]
//
// PantherClaw's ledger checkpoints have the origin
// "<evidence.log_origin>/org/<org id>" and no extension lines (PAP-1 §9.4).
type Checkpoint struct {
	Origin     string
	Size       uint64
	Root       merkle.Hash
	Extensions []string
}

// Text returns the checkpoint's note text.
func (c Checkpoint) Text() (string, error) {
	if err := c.check(); err != nil {
		return "", err
	}
	var b strings.Builder
	b.WriteString(c.Origin + "\n")
	b.WriteString(strconv.FormatUint(c.Size, 10) + "\n")
	b.WriteString(base64.StdEncoding.EncodeToString(c.Root[:]) + "\n")
	for _, e := range c.Extensions {
		b.WriteString(e + "\n")
	}
	return b.String(), nil
}

func (c Checkpoint) check() error {
	if c.Origin == "" || len(c.Origin) > MaxOriginBytes || strings.ContainsRune(c.Origin, '\n') {
		return fmt.Errorf("%w: checkpoint origin must be 1..%d bytes on one line", ErrMalformed, MaxOriginBytes)
	}
	if len(c.Extensions) > MaxExtensionLines {
		return fmt.Errorf("%w: more than %d extension lines", ErrMalformed, MaxExtensionLines)
	}
	for _, e := range c.Extensions {
		if e == "" || strings.ContainsRune(e, '\n') {
			return fmt.Errorf("%w: extension lines must be non-empty single lines", ErrMalformed)
		}
	}
	return checkText(c.Origin + "\n" + strings.Join(c.Extensions, "\n") + "\n")
}

// ParseCheckpoint parses checkpoint note text: an origin, a tree size in
// decimal without leading zeros, a canonical base64 root of 32 bytes, and
// non-empty extension lines.
func ParseCheckpoint(text string) (Checkpoint, error) {
	if err := checkText(text); err != nil {
		return Checkpoint{}, err
	}
	lines := strings.Split(strings.TrimSuffix(text, "\n"), "\n")
	if len(lines) < 3 {
		return Checkpoint{}, fmt.Errorf("%w: a checkpoint has at least 3 lines", ErrMalformed)
	}
	size, err := strconv.ParseUint(lines[1], 10, 64)
	if err != nil || strconv.FormatUint(size, 10) != lines[1] {
		return Checkpoint{}, fmt.Errorf("%w: invalid checkpoint tree size", ErrMalformed)
	}
	raw, err := decodeBase64(lines[2])
	if err != nil {
		return Checkpoint{}, fmt.Errorf("%w: invalid checkpoint root encoding", ErrMalformed)
	}
	root, err := merkle.HashFromBytes(raw)
	if err != nil {
		return Checkpoint{}, fmt.Errorf("%w: checkpoint root is not 32 bytes", ErrMalformed)
	}
	c := Checkpoint{Origin: lines[0], Size: size, Root: root}
	if len(lines) > 3 {
		c.Extensions = lines[3:]
	}
	if err := c.check(); err != nil {
		return Checkpoint{}, err
	}
	return c, nil
}

// SignCheckpoint signs c with each signer and returns the signed note.
func SignCheckpoint(c Checkpoint, signers ...Signer) ([]byte, error) {
	text, err := c.Text()
	if err != nil {
		return nil, err
	}
	return Sign(text, signers...)
}

// OpenCheckpoint verifies a signed checkpoint note against the known keys
// (Open) and parses its body, which must carry the expected origin. It
// returns the checkpoint and the signatures that verified.
func OpenCheckpoint(msg []byte, origin string, known ...Verifier) (Checkpoint, []Signature, error) {
	n, verified, err := Open(msg, known...)
	if err != nil {
		return Checkpoint{}, nil, err
	}
	c, err := ParseCheckpoint(n.Text)
	if err != nil {
		return Checkpoint{}, nil, err
	}
	if c.Origin != origin {
		return Checkpoint{}, nil, fmt.Errorf("%w: checkpoint origin %q, want %q", ErrMalformed, c.Origin, origin)
	}
	return c, verified, nil
}
