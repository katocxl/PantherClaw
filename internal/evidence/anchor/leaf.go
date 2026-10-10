// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package anchor

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"slices"

	"github.com/katocxl/pantherclaw/internal/evidence/merkle"
)

// LeafDomain separates anchor leaves from every other hash.
const LeafDomain = "pantherclaw.anchor-leaf.v1"

// NonceSize is the size of a leaf's blinding nonce.
const NonceSize = 32

// MaxLeaves caps the leaves of one anchor (one per org).
const MaxLeaves = 1 << 20

// ErrInvalidTree reports a malformed global tree or a leaf that is not in
// it.
var ErrInvalidTree = errors.New("anchor: invalid global tree")

// Nonce blinds one org's leaf in one anchor.
type Nonce [NonceSize]byte

// NewNonce draws a fresh random nonce. Every anchor draws a new one for
// every org, so the leaf of an org whose checkpoint did not change still
// changes (HR-195).
func NewNonce() (Nonce, error) {
	var n Nonce
	if _, err := rand.Read(n[:]); err != nil {
		return n, fmt.Errorf("anchor: nonce: %w", err)
	}
	return n, nil
}

// Leaf returns an org's blinded leaf for one anchor:
//
//	SHA-256(0x00 ‖ "pantherclaw.anchor-leaf.v1" ‖ nonce ‖ SHA-256(checkpoint note))
//
// which is the RFC 9162 leaf hash of the domain, the nonce and the digest
// of the org's latest signed checkpoint note. Without the nonce the leaf
// reveals neither the org nor whether its checkpoint changed.
func Leaf(nonce Nonce, checkpointNote []byte) merkle.Hash {
	d := sha256.Sum256(checkpointNote)
	data := make([]byte, 0, len(LeafDomain)+NonceSize+sha256.Size)
	data = append(data, LeafDomain...)
	data = append(data, nonce[:]...)
	data = append(data, d[:]...)
	return merkle.LeafHash(data)
}

// Tree is the global tree of one anchor: one leaf per org, ordered by the
// leaves' own values, so the order reveals nothing about the orgs.
type Tree struct {
	leaves []merkle.Hash
	tiles  *merkle.MemoryTiles
	root   merkle.Hash
}

// NewTree builds the global tree over leaves, sorting them. Duplicate
// leaves are refused (a fresh nonce makes them impossible).
func NewTree(leaves []merkle.Hash) (*Tree, error) {
	if len(leaves) == 0 || len(leaves) > MaxLeaves {
		return nil, fmt.Errorf("%w: 1..%d leaves", ErrInvalidTree, MaxLeaves)
	}
	sorted := slices.Clone(leaves)
	slices.SortFunc(sorted, func(a, b merkle.Hash) int { return bytes.Compare(a[:], b[:]) })
	for i := 1; i < len(sorted); i++ {
		if sorted[i].Equal(sorted[i-1]) {
			return nil, fmt.Errorf("%w: duplicate leaf", ErrInvalidTree)
		}
	}
	t := &Tree{leaves: sorted, tiles: merkle.NewMemoryTiles()}
	ctx := context.Background()
	if err := t.tiles.Append(ctx, sorted...); err != nil {
		return nil, err
	}
	root, err := merkle.Root(ctx, t.tiles, uint64(len(sorted)))
	if err != nil {
		return nil, err
	}
	t.root = root
	return t, nil
}

// TreeFromOrderedLeaves rebuilds the global tree from the leaves as an
// anchor lists them, which must already be in strictly ascending order.
func TreeFromOrderedLeaves(leaves []merkle.Hash) (*Tree, error) {
	for i := 1; i < len(leaves); i++ {
		if bytes.Compare(leaves[i-1][:], leaves[i][:]) >= 0 {
			return nil, fmt.Errorf("%w: leaves are not in ascending order", ErrInvalidTree)
		}
	}
	return NewTree(leaves)
}

// Root returns the global root.
func (t *Tree) Root() merkle.Hash { return t.root }

// Size returns the number of leaves.
func (t *Tree) Size() uint64 { return uint64(len(t.leaves)) }

// Leaves returns the leaves in tree order.
func (t *Tree) Leaves() []merkle.Hash { return slices.Clone(t.leaves) }

// InclusionProof returns the index of leaf in the tree and its inclusion
// proof.
func (t *Tree) InclusionProof(leaf merkle.Hash) (uint64, []merkle.Hash, error) {
	i, found := slices.BinarySearchFunc(t.leaves, leaf, func(a, b merkle.Hash) int { return bytes.Compare(a[:], b[:]) })
	if !found {
		return 0, nil, fmt.Errorf("%w: the leaf is not in the tree", ErrInvalidTree)
	}
	index := uint64(i) //nolint:gosec // G115: a position in the leaves, never negative
	p, err := merkle.InclusionProof(context.Background(), t.tiles, index, t.Size())
	if err != nil {
		return 0, nil, err
	}
	return index, p, nil
}
