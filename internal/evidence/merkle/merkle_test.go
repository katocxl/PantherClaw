// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package merkle

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"testing"

	"pgregory.net/rapid"
)

func hx(t testing.TB, s string) Hash {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	h, err := HashFromBytes(b)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func hxs(t testing.TB, ss ...string) []Hash {
	t.Helper()
	out := make([]Hash, 0, len(ss))
	for _, s := range ss {
		out = append(out, hx(t, s))
	}
	return out
}

// vectorLeaves are the leaf inputs of the RFC 6962 reference test vectors
// (certificate-transparency merkle_tree_test.cc, also used by RFC 9162
// implementations such as transparency-dev/merkle).
func vectorLeaves(t testing.TB) [][]byte {
	t.Helper()
	var out [][]byte
	for _, s := range []string{"", "00", "10", "2021", "3031", "40414243", "5051525354555657", "606162636465666768696a6b6c6d6e6f"} {
		b, err := hex.DecodeString(s)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, b)
	}
	return out
}

func vectorTree(t testing.TB) *MemoryTiles {
	t.Helper()
	m := NewMemoryTiles()
	for _, l := range vectorLeaves(t) {
		if err := m.Append(context.Background(), LeafHash(l)); err != nil {
			t.Fatal(err)
		}
	}
	return m
}

func TestHR194_RFC9162Vectors(t *testing.T) {
	ctx := context.Background()
	m := vectorTree(t)
	roots := hxs(t,
		"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		"6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
		"fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125",
		"aeb6bcfe274b70a14fb067a5e5578264db0fa9b51af5e0ba159158f329e06e77",
		"d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7",
		"4e3bbb1f7b478dcfe71fb631631519a3bca12c9aefca1612bfce4c13a86264d4",
		"76e67dadbcdf1e10e1b74ddc608abd2f98dfb16fbce75277b5232a127f2087ef",
		"ddb89be403809e325750d3d263cd78929c2942b7942a34b77e122c9594a74c8c",
		"5dc9da79a70659a9ad559cb701ded9a2ab9d823aad2f4960cfe370eff4604328",
	)
	if !EmptyRoot().Equal(roots[0]) {
		t.Fatal("empty root")
	}
	for size, want := range roots {
		got, err := Root(ctx, m, uint64(size))
		if err != nil || !got.Equal(want) {
			t.Fatalf("root(%d) = %x, %v; want %x", size, got, err, want)
		}
	}

	inclusion := []struct {
		index, size uint64
		proof       []Hash
	}{
		{0, 1, nil},
		{0, 8, hxs(t,
			"96a296d224f285c67bee93c30f8a309157f0daa35dc5b87e410b78630a09cfc7",
			"5f083f0a1a33ca076a95279832580db3e0ef4584bdff1f54c8a360f50de3031e",
			"6b47aaf29ee3c2af9af889bc1fb9254dabd31177f16232dd6aab035ca39bf6e4")},
		{5, 8, hxs(t,
			"bc1a0643b12e4d2d7c77918f44e0f4f79a838b6cf9ec5b5c283e1f4d88599e6b",
			"ca854ea128ed050b41b35ffc1b87b8eb2bde461e9e3b5596ece6b9d5975a0ae0",
			"d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7")},
		{2, 3, hxs(t, "fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125")},
		{1, 5, hxs(t,
			"6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
			"5f083f0a1a33ca076a95279832580db3e0ef4584bdff1f54c8a360f50de3031e",
			"bc1a0643b12e4d2d7c77918f44e0f4f79a838b6cf9ec5b5c283e1f4d88599e6b")},
	}
	leaves := vectorLeaves(t)
	for _, tc := range inclusion {
		got, err := InclusionProof(ctx, m, tc.index, tc.size)
		if err != nil || !equalHashes(got, tc.proof) {
			t.Fatalf("inclusion(%d, %d) = %x, %v", tc.index, tc.size, got, err)
		}
		if err := VerifyInclusion(LeafHash(leaves[tc.index]), tc.index, tc.size, tc.proof, roots[tc.size]); err != nil {
			t.Fatalf("verify inclusion(%d, %d): %v", tc.index, tc.size, err)
		}
	}

	consistency := []struct {
		m, n  uint64
		proof []Hash
	}{
		{1, 1, nil},
		{1, 8, hxs(t,
			"96a296d224f285c67bee93c30f8a309157f0daa35dc5b87e410b78630a09cfc7",
			"5f083f0a1a33ca076a95279832580db3e0ef4584bdff1f54c8a360f50de3031e",
			"6b47aaf29ee3c2af9af889bc1fb9254dabd31177f16232dd6aab035ca39bf6e4")},
		{6, 8, hxs(t,
			"0ebc5d3437fbe2db158b9f126a1d118e308181031d0a949f8dededebc558ef6a",
			"ca854ea128ed050b41b35ffc1b87b8eb2bde461e9e3b5596ece6b9d5975a0ae0",
			"d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7")},
		{2, 5, hxs(t,
			"5f083f0a1a33ca076a95279832580db3e0ef4584bdff1f54c8a360f50de3031e",
			"bc1a0643b12e4d2d7c77918f44e0f4f79a838b6cf9ec5b5c283e1f4d88599e6b")},
	}
	for _, tc := range consistency {
		got, err := ConsistencyProof(ctx, m, tc.m, tc.n)
		if err != nil || !equalHashes(got, tc.proof) {
			t.Fatalf("consistency(%d, %d) = %x, %v", tc.m, tc.n, got, err)
		}
		if err := VerifyConsistency(tc.m, tc.n, tc.proof, roots[tc.m], roots[tc.n]); err != nil {
			t.Fatalf("verify consistency(%d, %d): %v", tc.m, tc.n, err)
		}
	}
}

func TestHR194_TilePathsAndWidths(t *testing.T) {
	for _, tc := range []struct {
		id   TileID
		want string
	}{
		{TileID{0, 0, 256}, "tile/0/000"},
		{TileID{0, 1234067, 256}, "tile/0/x001/x234/067"},
		{TileID{1, 1000, 17}, "tile/1/x001/000.p/17"},
		{TileID{2, 999, 1}, "tile/2/999.p/1"},
	} {
		if got := tc.id.Path(); got != tc.want {
			t.Errorf("%+v path = %q, want %q", tc.id, got, tc.want)
		}
	}
	// c2sp.org/tlog-tiles: a tree of size 70,000 has 273 full level-0 tiles,
	// a partial level-0 tile of width 112, a full level-1 tile, a partial
	// level-1 tile of width 17 and a partial level-2 tile of width 1.
	tiles := TilesForSize(70000)
	count := map[[2]int]int{}
	for _, id := range tiles {
		count[[2]int{id.Level, id.Width}]++
	}
	want := map[[2]int]int{{0, 256}: 273, {0, 112}: 1, {1, 256}: 1, {1, 17}: 1, {2, 1}: 1}
	if fmt.Sprint(count) != fmt.Sprint(want) {
		t.Fatalf("tiles of 70000 = %v, want %v", count, want)
	}
	// A tree of size 256 is a full level-0 tile and a level-1 tile of width 1.
	if got := fmt.Sprint(TilesForSize(256)); got != "[{0 0 256} {1 0 1}]" {
		t.Fatalf("tiles of 256 = %s", got)
	}
}

// testLeaves returns n deterministic distinct leaf hashes.
func testLeaves(n int) []Hash {
	out := make([]Hash, n)
	for i := range out {
		var b [8]byte
		binary.BigEndian.PutUint64(b[:], uint64(i))
		d := sha256.Sum256(b[:])
		out[i] = LeafHash(d[:])
	}
	return out
}

// refRoot is a direct recursive RFC 9162 MTH over leaf hashes.
func refRoot(leaves []Hash) Hash {
	switch len(leaves) {
	case 0:
		return EmptyRoot()
	case 1:
		return leaves[0]
	}
	k := largestPowerOfTwoBelow(uint64(len(leaves)))
	return NodeHash(refRoot(leaves[:k]), refRoot(leaves[k:]))
}

func TestHR194_AppendInBatchesBuildsTheSameTiles(t *testing.T) {
	ctx := context.Background()
	leaves := testLeaves(70000)
	whole := NewMemoryTiles()
	if err := whole.Append(ctx, leaves...); err != nil {
		t.Fatal(err)
	}
	batched := NewMemoryTiles()
	for i, step := 0, 1; i < len(leaves); step = step*3%1031 + 1 {
		j := min(i+step, len(leaves))
		tiles, err := AppendTiles(ctx, batched, uint64(i), leaves[i:j])
		if err != nil {
			t.Fatal(err)
		}
		// Every changed tile has the width the new size gives it.
		for _, tl := range tiles {
			if w := tileWidthAt(uint64(j), tl.Level, tl.Index); w != tl.Width || len(tl.Hashes) != w*HashSize {
				t.Fatalf("size %d: tile %+v, want width %d", j, tl.TileID, w)
			}
		}
		batched.Put(tiles)
		i = j
	}
	for _, id := range TilesForSize(uint64(len(leaves))) {
		a, err1 := whole.ReadTile(ctx, id)
		b, err2 := batched.ReadTile(ctx, id)
		if err1 != nil || err2 != nil || string(a) != string(b) {
			t.Fatalf("tile %s differs (%v, %v)", id.Path(), err1, err2)
		}
	}
	got, err := Root(ctx, batched, uint64(len(leaves)))
	if err != nil || !got.Equal(refRoot(leaves)) {
		t.Fatalf("root = %x, %v", got, err)
	}
	// A size beyond the stored tree has no tiles.
	if _, err := Root(ctx, batched, uint64(len(leaves))+1); !errors.Is(err, ErrTileNotFound) {
		t.Fatalf("root beyond the tree: %v", err)
	}
}

// TestHR194_ProofsForEverySizeUpTo1024 checks the root of every tree size up
// to 1,024 against the reference, and inclusion and consistency proofs at
// the edges and the middle of each.
func TestHR194_ProofsForEverySizeUpTo1024(t *testing.T) {
	ctx := context.Background()
	leaves := testLeaves(1024)
	m := NewMemoryTiles()
	if err := m.Append(ctx, leaves...); err != nil {
		t.Fatal(err)
	}
	roots := make([]Hash, len(leaves)+1)
	for n := range roots {
		roots[n] = refRoot(leaves[:n])
	}
	for n := uint64(1); n <= 1024; n++ {
		root, err := Root(ctx, m, n)
		if err != nil || !root.Equal(roots[n]) {
			t.Fatalf("root(%d) = %x, %v", n, root, err)
		}
		for _, i := range []uint64{0, n / 2, n - 1} {
			p, err := InclusionProof(ctx, m, i, n)
			if err != nil {
				t.Fatal(err)
			}
			if err := VerifyInclusion(leaves[i], i, n, p, root); err != nil {
				t.Fatalf("inclusion(%d, %d): %v", i, n, err)
			}
		}
		for _, k := range []uint64{1, max(n/2, 1), max(n-1, 1), n} {
			p, err := ConsistencyProof(ctx, m, k, n)
			if err != nil {
				t.Fatal(err)
			}
			if err := VerifyConsistency(k, n, p, roots[k], root); err != nil {
				t.Fatalf("consistency(%d, %d): %v", k, n, err)
			}
		}
	}
}

// TestHR194_PropertyProofsVerifyAndTamperingFails: for any tree size up to
// 1,024, any leaf and any earlier size, the generated proofs verify, and any
// change to a proof, a leaf or a root makes them fail.
func TestHR194_PropertyProofsVerifyAndTamperingFails(t *testing.T) {
	ctx := context.Background()
	leaves := testLeaves(1024)
	m := NewMemoryTiles()
	if err := m.Append(ctx, leaves...); err != nil {
		t.Fatal(err)
	}
	rapid.Check(t, func(t *rapid.T) {
		n := rapid.Uint64Range(1, 1024).Draw(t, "n")
		i := rapid.Uint64Range(0, n-1).Draw(t, "i")
		k := rapid.Uint64Range(1, n).Draw(t, "k")
		root, err := Root(ctx, m, n)
		if err != nil {
			t.Fatal(err)
		}
		rootK, err := Root(ctx, m, k)
		if err != nil {
			t.Fatal(err)
		}
		inc, err := InclusionProof(ctx, m, i, n)
		if err != nil {
			t.Fatal(err)
		}
		if err := VerifyInclusion(leaves[i], i, n, inc, root); err != nil {
			t.Fatalf("inclusion: %v", err)
		}
		cons, err := ConsistencyProof(ctx, m, k, n)
		if err != nil {
			t.Fatal(err)
		}
		if err := VerifyConsistency(k, n, cons, rootK, root); err != nil {
			t.Fatalf("consistency: %v", err)
		}

		bad := Hash{0xff}
		if VerifyInclusion(bad, i, n, inc, root) == nil || VerifyInclusion(leaves[i], i, n, inc, bad) == nil {
			t.Fatal("inclusion verified with a changed leaf or root")
		}
		if VerifyInclusion(leaves[i], i, n, append(clone(inc), bad), root) == nil {
			t.Fatal("inclusion verified with an extra hash")
		}
		if len(inc) > 0 {
			j := rapid.IntRange(0, len(inc)-1).Draw(t, "j")
			tampered := clone(inc)
			tampered[j][rapid.IntRange(0, HashSize-1).Draw(t, "byte")] ^= 1
			if VerifyInclusion(leaves[i], i, n, tampered, root) == nil {
				t.Fatal("inclusion verified with a changed hash")
			}
			if VerifyInclusion(leaves[i], i, n, inc[:len(inc)-1], root) == nil {
				t.Fatal("inclusion verified with a missing hash")
			}
		}
		if k < n {
			if VerifyConsistency(k, n, cons, bad, root) == nil || VerifyConsistency(k, n, cons, rootK, bad) == nil {
				t.Fatal("consistency verified with a changed root")
			}
			if VerifyConsistency(k, n, append(clone(cons), bad), rootK, root) == nil {
				t.Fatal("consistency verified with an extra hash")
			}
			j := rapid.IntRange(0, len(cons)-1).Draw(t, "cj")
			tampered := clone(cons)
			tampered[j][rapid.IntRange(0, HashSize-1).Draw(t, "cbyte")] ^= 1
			if VerifyConsistency(k, n, tampered, rootK, root) == nil {
				t.Fatal("consistency verified with a changed hash")
			}
			if VerifyConsistency(k, n, cons[:len(cons)-1], rootK, root) == nil {
				t.Fatal("consistency verified with a missing hash")
			}
		}
	})
}

func TestVerifyRejectsMalformedParameters(t *testing.T) {
	h := Hash{1}
	for name, err := range map[string]error{
		"index beyond size":   VerifyInclusion(h, 3, 3, nil, h),
		"size zero":           VerifyInclusion(h, 0, 0, nil, h),
		"consistency from 0":  VerifyConsistency(0, 3, []Hash{h}, h, h),
		"consistency shrinks": VerifyConsistency(4, 3, []Hash{h}, h, h),
		"equal sizes, proof":  VerifyConsistency(3, 3, []Hash{h}, h, h),
		"equal sizes, roots":  VerifyConsistency(3, 3, nil, h, Hash{2}),
		"empty proof":         VerifyConsistency(2, 3, nil, h, h),
	} {
		if !errors.Is(err, ErrInvalidProof) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := HashFromBytes(make([]byte, 31)); !errors.Is(err, ErrInvalidProof) {
		t.Fatal("short hash accepted")
	}
	m := vectorTree(t)
	ctx := context.Background()
	if _, err := InclusionProof(ctx, m, 8, 8); err == nil {
		t.Fatal("inclusion proof beyond the tree")
	}
	if _, err := ConsistencyProof(ctx, m, 0, 8); err == nil {
		t.Fatal("consistency proof from size 0")
	}
}

// shortReader returns a tile with fewer hashes than asked, as a broken store
// would; the caller must not index past it.
type shortReader struct{}

func (shortReader) ReadTile(_ context.Context, t TileID) ([]byte, error) {
	return make([]byte, (t.Width-1)*HashSize+5), nil
}

func TestMalformedTileIsRejected(t *testing.T) {
	if _, err := Root(context.Background(), shortReader{}, 7); err == nil {
		t.Fatal("malformed tile accepted")
	}
}

func equalHashes(a, b []Hash) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if !a[i].Equal(b[i]) {
			return false
		}
	}
	return true
}

func clone(h []Hash) []Hash { return append([]Hash(nil), h...) }
