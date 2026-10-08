// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package page implements cursor pagination for list endpoints (BUILD_GUIDE
// §3.2): page sizes default to 50 and are capped at 200, and the opaque page
// token is the base64url id of the last row scanned (ids are UUIDv7, so id
// order is creation order).
package page

import (
	"encoding/base64"

	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// Size limits.
const (
	Default = 50
	Max     = 200
)

// ErrBadToken reports a page token this server did not produce.
var ErrBadToken = pcerr.New(pcerr.InvalidArgument, "INVALID_PAGE_TOKEN", "invalid page token")

// Request is a decoded page request.
type Request struct {
	// After is the id to continue after (zero for the first page).
	After ids.UUID
	// Size is the number of results wanted.
	Size int
}

// Limit is the LIMIT to query with: one more than Size, so Finish can tell
// whether another page exists.
func (r Request) Limit() int32 { return int32(min(r.Size, Max) + 1) } //nolint:gosec // G115: bounded by Max

// Parse decodes a page size and token.
func Parse(size int32, token string) (Request, error) {
	r := Request{Size: Default}
	if size > 0 {
		r.Size = int(min(size, Max))
	}
	if token == "" {
		return r, nil
	}
	b, err := base64.RawURLEncoding.Strict().DecodeString(token)
	if err != nil || len(b) != len(r.After) {
		return Request{}, ErrBadToken
	}
	copy(r.After[:], b)
	if r.After.IsZero() || r.After.Version() != 7 {
		return Request{}, ErrBadToken
	}
	return r, nil
}

// Finish trims rows fetched with Limit to the page size and returns them
// with the next page token ("" on the last page).
func Finish[T any](r Request, rows []T, id func(T) ids.UUID) ([]T, string) {
	if len(rows) <= r.Size {
		return rows, ""
	}
	rows = rows[:r.Size]
	last := id(rows[len(rows)-1])
	return rows, base64.RawURLEncoding.EncodeToString(last[:])
}
