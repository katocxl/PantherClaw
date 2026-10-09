// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package sim

import (
	"bytes"
	"context"
	"encoding/json/v2"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"connectrpc.com/connect/v2"
	"connectrpc.com/connect/v2/connecthttp"

	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	"github.com/katocxl/pantherclaw/internal/identity/workloadclient"
)

func TestUniqueRefundsNeverRepeat(t *testing.T) {
	for i, want := range map[int][2]string{
		0: {"ch_tagn0", "0.01"}, 99: {"ch_tagn0", "1.00"}, 9998: {"ch_tagn0", "99.99"}, 9999: {"ch_tagn1", "0.01"},
	} {
		if c, a := uniqueRefund("tag", i); c != want[0] || a != want[1] {
			t.Errorf("uniqueRefund(%d) = %s %s, want %v", i, c, a, want)
		}
	}
	// No pair repeats within a run, nor across two runs.
	first, second := runTag(time.Unix(1, 0)), runTag(time.Unix(2, 0))
	seen := map[[2]string]bool{}
	for _, tag := range []string{first, second} {
		for i := range 3 * amountsPerCharge {
			c, a := uniqueRefund(tag, i)
			if seen[[2]string{c, a}] {
				t.Fatalf("request %d of run %s repeats %s %s", i, tag, c, a)
			}
			seen[[2]string{c, a}] = true
		}
	}
	if got := chargesFor("tag", 2*amountsPerCharge+1, true); len(got) != 3 || got[2] != "ch_tagn2" {
		t.Fatalf("chargesFor = %v", got)
	}
	if got := chargesFor("tag", 5, false); len(got) != 1 || got[0] != "ch_load1" {
		t.Fatalf("chargesFor without --unique = %v", got)
	}
}

type recordFacts struct {
	pantherclawv1connect.UnimplementedFactServiceHandler
	mu       sync.Mutex
	subjects []string
	auth     string
}

func (r *recordFacts) PutFacts(_ context.Context, req *pantherclawv1.PutFactsRequest) (*pantherclawv1.PutFactsResponse, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := &pantherclawv1.PutFactsResponse{}
	for i, o := range req.GetObservations() {
		r.subjects = append(r.subjects, o.GetSubjectId())
		out.Results = append(out.Results, &pantherclawv1.FactResult{Index: int32(i), Accepted: o.GetName() == "payments.charge.refundable"})
	}
	return out, nil
}

// TestLoadReportsFactsAndVariesRefunds: with --facts-key-file the charges
// are reported as refundable before the first refund, with the API key;
// with --unique no two refunds share a charge and amount.
func TestLoadReportsFactsAndVariesRefunds(t *testing.T) {
	facts := &recordFacts{}
	cs := connect.NewServer()
	pantherclawv1connect.RegisterFactServiceHandler(cs, facts)
	mux := http.NewServeMux()
	connecthttp.Mount(mux, cs)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		facts.mu.Lock()
		facts.auth = r.Header.Get("Authorization")
		facts.mu.Unlock()
		mux.ServeHTTP(w, r)
	}))
	defer server.Close()

	var mu sync.Mutex
	bodies := map[string]bool{}
	gw := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		var in struct {
			Charge string `json:"charge"`
			Amount string `json:"amount"`
		}
		_ = json.Unmarshal(b, &in)
		facts.mu.Lock()
		reported := len(facts.subjects) > 0
		facts.mu.Unlock()
		mu.Lock()
		defer mu.Unlock()
		if !reported || bodies[in.Charge+"/"+in.Amount] {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		bodies[in.Charge+"/"+in.Amount] = true
		_, _ = w.Write([]byte(`{"outcome":"ACCEPTED"}`))
	}))
	defer gw.Close()

	dir := t.TempDir()
	kf, _, err := workloadclient.NewKeyFile()
	if err != nil {
		t.Fatal(err)
	}
	kf.Server = server.URL
	keyFile, tokenFile, factsKey := filepath.Join(dir, "workload.json"), filepath.Join(dir, "token"), filepath.Join(dir, "facts.key")
	if err := workloadclient.WriteKeyFile(keyFile, kf, false); err != nil {
		t.Fatal(err)
	}
	for p, v := range map[string]string{tokenFile: "tok-1\n", factsKey: "pck_test_facts\n"} {
		if err := os.WriteFile(p, []byte(v), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	var stdout, stderr bytes.Buffer
	args := []string{
		"load", "--gateway", gw.URL, "--workload-file", keyFile, "--token-file", tokenFile, "--run", "run-1",
		"--rate", "100", "--duration", "500ms", "--warmup", "0s", "--unique", "--facts-key-file", factsKey,
	}
	if code := Run(context.Background(), args, &stdout, &stderr); code != 0 {
		t.Fatalf("load: %d %s", code, stderr.String())
	}
	if len(facts.subjects) != 1 || !strings.HasSuffix(facts.subjects[0], "n0") || facts.auth != "Bearer pck_test_facts" {
		t.Fatalf("facts reported %v with %q", facts.subjects, facts.auth)
	}
	if len(bodies) != 50 || !bytes.Contains(stdout.Bytes(), []byte("statuses: map[200:")) || bytes.Contains(stdout.Bytes(), []byte("403")) {
		t.Fatalf("%d distinct refunds; summary:\n%s", len(bodies), stdout.String())
	}
}
