// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package merkle

import (
	"context"
	"fmt"
	"math/bits"
)

// nodes reads complete subtree hashes from tiles, caching each tile it read
// for the duration of one computation.
type nodes struct {
	r     TileReader
	cache map[tileKey][]byte
}

func newNodes(r TileReader) *nodes { return &nodes{r: r, cache: map[tileKey][]byte{}} }

// node returns the hash of the complete subtree of 2^height leaves with the
// given index among the subtrees of that height. The subtree lies inside one
// tile: tile level height/8 holds its descendants at tree level 8·(height/8).
func (s *nodes) node(ctx context.Context, height int, index uint64) (Hash, error) {
	level, sub := height/TileHeight, height%TileHeight
	first := index << sub
	idx, off := first/TileWidth, int(first%TileWidth)
	width := off + 1<<sub
	k := tileKey{level, idx}
	b := s.cache[k]
	if len(b) < width*HashSize {
		var err error
		if b, err = readTile(ctx, s.r, TileID{Level: level, Index: idx, Width: width}); err != nil {
			return Hash{}, err
		}
		s.cache[k] = b
	}
	return subtreeRoot(b[off*HashSize:width*HashSize], sub), nil
}

// rangeHash returns MTH(D[lo:hi]) (RFC 9162 §2.1.1) for 0 ≤ lo < hi.
func (s *nodes) rangeHash(ctx context.Context, lo, hi uint64) (Hash, error) {
	n := hi - lo
	if isPowerOfTwo(n) && lo%n == 0 {
		return s.node(ctx, bits.TrailingZeros64(n), lo/n)
	}
	k := largestPowerOfTwoBelow(n)
	left, err := s.rangeHash(ctx, lo, lo+k)
	if err != nil {
		return Hash{}, err
	}
	right, err := s.rangeHash(ctx, lo+k, hi)
	if err != nil {
		return Hash{}, err
	}
	return NodeHash(left, right), nil
}

// Root returns the root of the tree of the given size whose tiles r holds.
func Root(ctx context.Context, r TileReader, size uint64) (Hash, error) {
	if size == 0 {
		return EmptyRoot(), nil
	}
	return newNodes(r).rangeHash(ctx, 0, size)
}

// InclusionProof returns the RFC 9162 inclusion proof (§2.1.3.1) of leaf
// index in the tree of the given size.
func InclusionProof(ctx context.Context, r TileReader, index, size uint64) ([]Hash, error) {
	if index >= size {
		return nil, fmt.Errorf("merkle: leaf %d is not in a tree of size %d", index, size)
	}
	return newNodes(r).path(ctx, index, 0, size)
}

// path is PATH(m, D[lo:hi]) with m relative to lo.
func (s *nodes) path(ctx context.Context, m, lo, hi uint64) ([]Hash, error) {
	n := hi - lo
	if n <= 1 {
		return nil, nil
	}
	k := largestPowerOfTwoBelow(n)
	var (
		p       []Hash
		sibling Hash
		err     error
	)
	if m < k {
		if p, err = s.path(ctx, m, lo, lo+k); err == nil {
			sibling, err = s.rangeHash(ctx, lo+k, hi)
		}
	} else {
		if p, err = s.path(ctx, m-k, lo+k, hi); err == nil {
			sibling, err = s.rangeHash(ctx, lo, lo+k)
		}
	}
	if err != nil {
		return nil, err
	}
	return append(p, sibling), nil
}

// ConsistencyProof returns the RFC 9162 consistency proof (§2.1.4.1) from
// the tree of size m to the tree of size n, 0 < m ≤ n. It is empty when
// m = n.
func ConsistencyProof(ctx context.Context, r TileReader, m, n uint64) ([]Hash, error) {
	if m == 0 || m > n {
		return nil, fmt.Errorf("merkle: no consistency proof from size %d to size %d", m, n)
	}
	if m == n {
		return nil, nil
	}
	return newNodes(r).subproof(ctx, m, 0, n, true)
}

// subproof is SUBPROOF(m, D[lo:hi], b).
func (s *nodes) subproof(ctx context.Context, m, lo, hi uint64, b bool) ([]Hash, error) {
	n := hi - lo
	if m == n {
		if b {
			return nil, nil
		}
		h, err := s.rangeHash(ctx, lo, hi)
		if err != nil {
			return nil, err
		}
		return []Hash{h}, nil
	}
	k := largestPowerOfTwoBelow(n)
	var (
		p       []Hash
		sibling Hash
		err     error
	)
	if m <= k {
		if p, err = s.subproof(ctx, m, lo, lo+k, b); err == nil {
			sibling, err = s.rangeHash(ctx, lo+k, hi)
		}
	} else {
		if p, err = s.subproof(ctx, m-k, lo+k, hi, false); err == nil {
			sibling, err = s.rangeHash(ctx, lo, lo+k)
		}
	}
	if err != nil {
		return nil, err
	}
	return append(p, sibling), nil
}

// VerifyInclusion checks an inclusion proof of the leaf hash at index in the
// tree of the given size against its root (RFC 9162 §2.1.3.2).
func VerifyInclusion(leaf Hash, index, size uint64, proof []Hash, root Hash) error {
	if index >= size {
		return fmt.Errorf("%w: leaf %d is not in a tree of size %d", ErrInvalidProof, index, size)
	}
	fn, sn := index, size-1
	r := leaf
	for _, p := range proof {
		if sn == 0 {
			return fmt.Errorf("%w: inclusion proof is too long", ErrInvalidProof)
		}
		if fn&1 == 1 || fn == sn {
			r = NodeHash(p, r)
			for fn&1 == 0 && fn != 0 {
				fn >>= 1
				sn >>= 1
			}
		} else {
			r = NodeHash(r, p)
		}
		fn >>= 1
		sn >>= 1
	}
	if sn != 0 {
		return fmt.Errorf("%w: inclusion proof is too short", ErrInvalidProof)
	}
	if !r.Equal(root) {
		return fmt.Errorf("%w: inclusion proof does not lead to the root", ErrInvalidProof)
	}
	return nil
}

// VerifyConsistency checks a consistency proof from the tree of size m with
// root rootM to the tree of size n with root rootN (RFC 9162 §2.1.4.2),
// 0 < m ≤ n.
func VerifyConsistency(m, n uint64, proof []Hash, rootM, rootN Hash) error {
	switch {
	case m == 0 || m > n:
		return fmt.Errorf("%w: no consistency proof from size %d to size %d", ErrInvalidProof, m, n)
	case m == n:
		if len(proof) != 0 {
			return fmt.Errorf("%w: a proof between equal sizes must be empty", ErrInvalidProof)
		}
		if !rootM.Equal(rootN) {
			return fmt.Errorf("%w: different roots for the same size", ErrInvalidProof)
		}
		return nil
	case len(proof) == 0:
		return fmt.Errorf("%w: empty consistency proof", ErrInvalidProof)
	}
	if isPowerOfTwo(m) {
		proof = append([]Hash{rootM}, proof...)
	}
	fn, sn := m-1, n-1
	for fn&1 == 1 {
		fn >>= 1
		sn >>= 1
	}
	fr, sr := proof[0], proof[0]
	for _, c := range proof[1:] {
		if sn == 0 {
			return fmt.Errorf("%w: consistency proof is too long", ErrInvalidProof)
		}
		if fn&1 == 1 || fn == sn {
			fr = NodeHash(c, fr)
			sr = NodeHash(c, sr)
			for fn&1 == 0 && fn != 0 {
				fn >>= 1
				sn >>= 1
			}
		} else {
			sr = NodeHash(sr, c)
		}
		fn >>= 1
		sn >>= 1
	}
	if sn != 0 {
		return fmt.Errorf("%w: consistency proof is too short", ErrInvalidProof)
	}
	if !fr.Equal(rootM) || !sr.Equal(rootN) {
		return fmt.Errorf("%w: consistency proof does not lead to both roots", ErrInvalidProof)
	}
	return nil
}
