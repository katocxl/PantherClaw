// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package merkle

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"sync"
)

// Tiles follow C2SP tlog-tiles (c2sp.org/tlog-tiles) with height 8. The tile
// at level L and index N holds up to 256 consecutive hashes of the tree's
// level 8·L: leaf hashes at level 0, and at level L ≥ 1 the root of each
// full tile of level L−1. The rightmost tile of a level may be partial
// (width 1..255); partial tiles are never hashed into the level above. A tile
// is stored as the concatenation of its hashes.
const (
	// TileHeight is the number of tree levels a tile covers.
	TileHeight = 8
	// TileWidth is the number of hashes in a full tile.
	TileWidth = 1 << TileHeight
	// MaxTileLevel is the highest tile level of the format.
	MaxTileLevel = 63
)

// TileID names a tile and its width.
type TileID struct {
	Level int
	Index uint64
	Width int
}

// Valid reports whether t is a tile of the format.
func (t TileID) Valid() bool {
	return t.Level >= 0 && t.Level <= MaxTileLevel && t.Width >= 1 && t.Width <= TileWidth
}

// Path returns the tile's C2SP path relative to the log prefix:
// tile/<L>/<N>, with N in zero-padded 3-digit elements all but the last
// prefixed with "x", and ".p/<W>" for a partial tile.
func (t TileID) Path() string {
	p := "tile/" + strconv.Itoa(t.Level) + "/" + indexPath(t.Index)
	if t.Width < TileWidth {
		p += ".p/" + strconv.Itoa(t.Width)
	}
	return p
}

func indexPath(n uint64) string {
	elems := []string{fmt.Sprintf("%03d", n%1000)}
	for n >= 1000 {
		n /= 1000
		elems = append(elems, fmt.Sprintf("x%03d", n%1000))
	}
	for i, j := 0, len(elems)-1; i < j; i, j = i+1, j-1 {
		elems[i], elems[j] = elems[j], elems[i]
	}
	return strings.Join(elems, "/")
}

// tileKey names a tile regardless of its width.
type tileKey struct {
	level int
	index uint64
}

// Tile is a tile with its hashes, Width·32 bytes.
type Tile struct {
	TileID
	Hashes []byte
}

// Hash returns the i-th hash of the tile.
func (t Tile) Hash(i int) Hash {
	var h Hash
	copy(h[:], t.Hashes[i*HashSize:(i+1)*HashSize])
	return h
}

// TileReader reads stored tiles. ReadTile returns the hashes of tile
// (t.Level, t.Index) concatenated, at least t.Width of them; a wider stored
// tile is fine, and only its first t.Width hashes are used. A tile the store
// does not hold, or holds narrower, is ErrTileNotFound.
type TileReader interface {
	ReadTile(ctx context.Context, t TileID) ([]byte, error)
}

// tileWidthAt returns the width of tile index at a level for a tree of size
// n, or 0 when the tree has no such tile.
func tileWidthAt(n uint64, level int, index uint64) int {
	entries := levelEntries(n, level)
	start := index * TileWidth
	if entries <= start {
		return 0
	}
	return int(min(entries-start, TileWidth))
}

// levelEntries is the number of hashes at tile level `level` (tree level
// 8·level) that a tree of size n has: one per complete subtree of that height.
func levelEntries(n uint64, level int) uint64 {
	if TileHeight*level >= 64 {
		return 0
	}
	return n >> (TileHeight * level)
}

// TilesForSize lists every tile of a tree of size n, partial ones included.
func TilesForSize(n uint64) []TileID {
	var out []TileID
	for level := 0; level <= MaxTileLevel; level++ {
		entries := levelEntries(n, level)
		if entries == 0 {
			break
		}
		for idx := uint64(0); idx*TileWidth < entries; idx++ {
			out = append(out, TileID{Level: level, Index: idx, Width: tileWidthAt(n, level, idx)})
		}
	}
	return out
}

// AppendTiles returns the tiles that a tree of size oldSize gains or widens
// when the leaf hashes leaves are appended to it, at every level, full and
// partial, in level then index order. r holds the tiles of the tree of size
// oldSize; only its partial tiles are read. The new tree's size is
// oldSize + len(leaves).
func AppendTiles(ctx context.Context, r TileReader, oldSize uint64, leaves []Hash) ([]Tile, error) {
	if uint64(len(leaves)) > ^uint64(0)-oldSize {
		return nil, fmt.Errorf("merkle: tree size overflows")
	}
	var out []Tile
	entries := leaves // new hashes at this level, from index start on
	start := oldSize  // hashes this level already had
	for level := 0; len(entries) > 0; level++ {
		if level > MaxTileLevel {
			return nil, fmt.Errorf("merkle: tree too large")
		}
		idx := start / TileWidth
		off := int(start % TileWidth)
		row := make([]byte, 0, (off+len(entries))*HashSize)
		if off > 0 {
			old, err := readTile(ctx, r, TileID{Level: level, Index: idx, Width: off})
			if err != nil {
				return nil, err
			}
			row = append(row, old...)
		}
		for _, h := range entries {
			row = append(row, h[:]...)
		}
		var next []Hash
		for len(row) > 0 {
			n := min(len(row)/HashSize, TileWidth)
			t := Tile{TileID: TileID{Level: level, Index: idx, Width: n}, Hashes: row[: n*HashSize : n*HashSize]}
			out = append(out, t)
			if n == TileWidth {
				next = append(next, subtreeRoot(t.Hashes, TileHeight))
			}
			row = row[n*HashSize:]
			idx++
		}
		entries, start = next, start/TileWidth
	}
	return out, nil
}

// subtreeRoot hashes 2^height consecutive hashes up to their subtree root.
func subtreeRoot(hashes []byte, height int) Hash {
	level := make([]Hash, len(hashes)/HashSize)
	for i := range level {
		copy(level[i][:], hashes[i*HashSize:])
	}
	for range height {
		for i := range len(level) / 2 {
			level[i] = NodeHash(level[2*i], level[2*i+1])
		}
		level = level[:len(level)/2]
	}
	return level[0]
}

// readTile reads a tile and returns exactly its first t.Width hashes.
func readTile(ctx context.Context, r TileReader, t TileID) ([]byte, error) {
	if !t.Valid() {
		return nil, fmt.Errorf("merkle: invalid tile %+v", t)
	}
	b, err := r.ReadTile(ctx, t)
	if err != nil {
		return nil, fmt.Errorf("merkle: read %s: %w", t.Path(), err)
	}
	if len(b)%HashSize != 0 || len(b) > TileWidth*HashSize {
		return nil, fmt.Errorf("merkle: tile %s is malformed (%d bytes)", t.Path(), len(b))
	}
	if len(b) < t.Width*HashSize {
		return nil, fmt.Errorf("%w: %s holds %d hashes", ErrTileNotFound, t.Path(), len(b)/HashSize)
	}
	return b[:t.Width*HashSize], nil
}

// MemoryTiles is an in-memory tile store that keeps the widest version of
// each tile. It is safe for concurrent use.
type MemoryTiles struct {
	appendMu sync.Mutex // one Append at a time
	mu       sync.RWMutex
	tiles    map[tileKey][]byte
	size     uint64
}

// NewMemoryTiles returns an empty store (a tree of size 0).
func NewMemoryTiles() *MemoryTiles { return &MemoryTiles{tiles: map[tileKey][]byte{}} }

// ReadTile implements TileReader.
func (m *MemoryTiles) ReadTile(_ context.Context, t TileID) ([]byte, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	b, ok := m.tiles[tileKey{t.Level, t.Index}]
	if !ok || len(b) < t.Width*HashSize {
		return nil, ErrTileNotFound
	}
	return b[: t.Width*HashSize : t.Width*HashSize], nil
}

// Put stores tiles, keeping the widest version of each.
func (m *MemoryTiles) Put(tiles []Tile) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, t := range tiles {
		k := tileKey{t.Level, t.Index}
		if len(t.Hashes) > len(m.tiles[k]) {
			m.tiles[k] = append([]byte(nil), t.Hashes...)
		}
	}
}

// Size returns the tree size of the leaves appended with Append.
func (m *MemoryTiles) Size() uint64 {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.size
}

// Append appends leaf hashes to the tree and stores the changed tiles.
func (m *MemoryTiles) Append(ctx context.Context, leaves ...Hash) error {
	m.appendMu.Lock()
	defer m.appendMu.Unlock()
	size := m.Size()
	tiles, err := AppendTiles(ctx, m, size, leaves)
	if err != nil {
		return err
	}
	m.Put(tiles)
	m.mu.Lock()
	m.size = size + uint64(len(leaves))
	m.mu.Unlock()
	return nil
}
