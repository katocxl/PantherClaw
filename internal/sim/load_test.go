// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package sim

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestServerTimingParsing(t *testing.T) {
	got := serverTiming([]string{"build;dur=0.010", "authz;dur=3.5, verify;dur=0.2", "target;dur=1.25", "junk", "total;dur=x"})
	if got["authz"] != 3.5 || got["verify"] != 0.2 || got["target"] != 1.25 || len(got) != 4 {
		t.Fatalf("serverTiming = %v", got)
	}
}

func TestPercentiles(t *testing.T) {
	xs := make([]float64, 100)
	for i := range xs {
		xs[99-i] = float64(i + 1)
	}
	p := percentiles(xs)
	if p["p50"] != 51 || p["p95"] != 96 || p["p99"] != 100 || p["max"] != 100 {
		t.Fatalf("percentiles = %v", p)
	}
	if len(percentiles(nil)) != 0 {
		t.Fatal("empty input produced percentiles")
	}
}

func TestLoadDrivesAtTheTargetRate(t *testing.T) {
	var calls atomic.Int64
	gw := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Header.Get("PC-Dev-Workload") != "w-1" || r.Header.Get("PC-Action-Id") == "" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Add("Server-Timing", "authz;dur=2.000")
		w.Header().Add("Server-Timing", "target;dur=1.000")
		w.Header().Add("Server-Timing", "total;dur=4.000")
		_, _ = w.Write([]byte(`{"outcome":"ACCEPTED"}`))
	}))
	defer gw.Close()
	out := filepath.Join(t.TempDir(), "summary.json")
	var stdout, stderr bytes.Buffer
	args := []string{"load", "--gateway", gw.URL, "--workload", "w-1", "--rate", "200", "--duration", "1s", "--warmup", "200ms", "--out", out}
	if code := Run(context.Background(), args, &stdout, &stderr); code != 0 {
		t.Fatalf("load: %d %s", code, stderr.String())
	}
	if n := calls.Load(); n < 230 || n > 250 {
		t.Fatalf("sent %d requests, want about 240 (200 rps for 1.2 s)", n)
	}
	s := stdout.String()
	for _, want := range []string{"SIMULATED load", "statuses: map[200:", "authorize", "gateway_overhead"} {
		if !strings.Contains(s, want) {
			t.Fatalf("summary lacks %q:\n%s", want, s)
		}
	}
	// gateway overhead = total - target = 3 ms for every request.
	if !strings.Contains(s, "gateway_overhead        3.00      3.00      3.00      3.00") {
		t.Fatalf("overhead not derived from Server-Timing:\n%s", s)
	}
}

func TestLoadRequiresAWorkload(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := Run(context.Background(), []string{"load", "--duration", "1s"}, &stdout, &stderr); code != 2 {
		t.Fatalf("load without workload = %d", code)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if code := Run(ctx, []string{"load", "--workload", "w", "--gateway", "http://127.0.0.1:1", "--rate", "1", "--duration", "10s"}, &stdout, &stderr); code != 1 {
		t.Fatalf("canceled load = %d", code)
	}
}
