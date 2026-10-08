// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package sim

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"
)

func TestRunUsageAndVersion(t *testing.T) {
	var out, errb bytes.Buffer
	if code := Run(context.Background(), []string{"payments", "--bogus"}, &out, &errb); code == 0 {
		t.Error("unknown flag accepted")
	}
	for _, args := range [][]string{nil, {"bogus"}} {
		if code := Run(context.Background(), args, &out, &errb); code != 2 {
			t.Errorf("%v: %d, want 2", args, code)
		}
	}
	if code := Run(context.Background(), []string{"version"}, &out, &errb); code != 0 || !strings.HasPrefix(out.String(), "pantherclaw-sim ") {
		t.Fatalf("version: %d %q", code, out.String())
	}
}

func TestPaymentsStopsOnCancel(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	var out, errb bytes.Buffer
	if code := Run(ctx, []string{"payments", "--addr", "127.0.0.1:0"}, &out, &errb); code != 0 {
		t.Fatalf("payments: %d %s", code, errb.String())
	}
	if !strings.Contains(errb.String(), "sim.payments_listening") {
		t.Fatalf("no listening log: %s", errb.String())
	}
}
