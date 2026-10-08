// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package page_test

import (
	"errors"
	"testing"

	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/page"
)

func TestPaging(t *testing.T) {
	r, err := page.Parse(0, "")
	if err != nil || r.Size != page.Default || !r.After.IsZero() || r.Limit() != page.Default+1 {
		t.Fatalf("default: %+v %v", r, err)
	}
	if r, _ := page.Parse(5000, ""); r.Size != page.Max {
		t.Fatalf("size not capped: %d", r.Size)
	}
	rows := make([]ids.UUID, 4)
	for i := range rows {
		rows[i] = ids.NewV7()
	}
	r, _ = page.Parse(3, "")
	got, next := page.Finish(r, rows, func(u ids.UUID) ids.UUID { return u })
	if len(got) != 3 || next == "" {
		t.Fatalf("first page: %d rows, next %q", len(got), next)
	}
	r2, err := page.Parse(3, next)
	if err != nil || r2.After != rows[2] {
		t.Fatalf("token round trip: %v %v", r2.After, err)
	}
	if got, next := page.Finish(r2, rows[3:], func(u ids.UUID) ids.UUID { return u }); len(got) != 1 || next != "" {
		t.Fatalf("last page: %d rows, next %q", len(got), next)
	}
	for _, bad := range []string{"!", "AAAA", "AAAAAAAAAAAAAAAAAAAAAA", "x" + next} {
		if _, err := page.Parse(10, bad); !errors.Is(err, page.ErrBadToken) {
			t.Errorf("token %q: %v", bad, err)
		}
	}
}
