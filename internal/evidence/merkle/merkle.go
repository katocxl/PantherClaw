// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package merkle implements the Merkle tree of the evidence ledger (G0 M7
// design decision 8, HR-194, PAP-1 §9.4): RFC 9162 hashing, the C2SP
// tlog-tiles storage format, and inclusion and consistency proofs, generated
// from tiles and verified. It uses only the standard library and performs no
// I/O of its own: tiles come from a TileReader.
//
// Hashing (RFC 9162 §2.1.1):
//
//	leaf hash = SHA-256(0x00 ‖ leaf data)
//	node hash = SHA-256(0x01 ‖ left ‖ right)
//	empty root = SHA-256("")
//
// An org's ledger tree has one leaf per chained entry, in sequence order, and
// the leaf data is the entry's 32-byte entry_hash.
package merkle

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"math/bits"
)

// HashSize is the size of every hash in the tree (SHA-256).
const HashSize = sha256.Size

// Hash is a leaf, node or root hash.
type Hash [HashSize]byte

// LeafHash returns the RFC 9162 hash of a leaf.
func LeafHash(data []byte) Hash {
	h := sha256.New()
	h.Write([]byte{0x00})
	h.Write(data)
	var out Hash
	h.Sum(out[:0])
	return out
}

// NodeHash returns the RFC 9162 hash of an interior node.
func NodeHash(left, right Hash) Hash {
	var buf [1 + 2*HashSize]byte
	buf[0] = 0x01
	copy(buf[1:], left[:])
	copy(buf[1+HashSize:], right[:])
	return sha256.Sum256(buf[:])
}

// EmptyRoot is the root of the tree of size 0.
func EmptyRoot() Hash { return sha256.Sum256(nil) }

// HashFromBytes copies a 32-byte slice into a Hash.
func HashFromBytes(b []byte) (Hash, error) {
	var h Hash
	if len(b) != HashSize {
		return h, fmt.Errorf("%w: hash is %d bytes, want %d", ErrInvalidProof, len(b), HashSize)
	}
	copy(h[:], b)
	return h, nil
}

// Equal reports whether two hashes are equal.
func (h Hash) Equal(o Hash) bool { return bytes.Equal(h[:], o[:]) }

var (
	// ErrInvalidProof reports a proof that does not verify, or malformed
	// proof parameters.
	ErrInvalidProof = errors.New("merkle: invalid proof")
	// ErrTileNotFound reports a tile the store does not hold, or holds with
	// fewer hashes than needed.
	ErrTileNotFound = errors.New("merkle: tile not found")
)

// largestPowerOfTwoBelow returns the largest power of two strictly smaller
// than n (n ≥ 2), the split point k of RFC 9162 §2.1.1.
func largestPowerOfTwoBelow(n uint64) uint64 {
	return 1 << (bits.Len64(n-1) - 1)
}

// isPowerOfTwo reports whether n is a power of two (n ≥ 1).
func isPowerOfTwo(n uint64) bool { return n != 0 && n&(n-1) == 0 }
