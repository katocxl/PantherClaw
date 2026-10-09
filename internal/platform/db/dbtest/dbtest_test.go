// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package dbtest

import (
	"testing"
	"time"
)

func TestLastUsedCommentRoundTrips(t *testing.T) {
	at := time.Date(2026, 10, 9, 14, 30, 5, 0, time.FixedZone("CEST", 2*3600))
	got, ok := parseLastUsed(lastUsedComment(at))
	if !ok || !got.Equal(at) {
		t.Fatalf("parseLastUsed(lastUsedComment(%v)) = %v, %v", at, got, ok)
	}
	for _, c := range []string{"", "a comment someone else wrote", lastUsedPrefix + "yesterday"} {
		if _, ok := parseLastUsed(c); ok {
			t.Errorf("parseLastUsed(%q) accepted a comment markUsed did not write", c)
		}
	}
}
