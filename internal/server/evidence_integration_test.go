// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package server

import (
	"bytes"
	"context"
	"encoding/json/v2"
	"errors"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/evidence/bundle"
	"github.com/katocxl/pantherclaw/internal/evidence/keydocs"
	"github.com/katocxl/pantherclaw/internal/platform/db/dbtest"
)

// serveForTest starts cmdServe with cfgPath and returns its base URL; the
// server stops when the test ends.
func serveForTest(t *testing.T, cfgPath string) string {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	addrCh := make(chan string, 1)
	done := make(chan error, 1)
	var logs bytes.Buffer
	go func() {
		done <- cmdServe(ctx, []string{"--config", cfgPath}, &logs, noEnv, func(a string) { addrCh <- a })
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(30 * time.Second):
			t.Error("server did not stop")
		}
	})
	select {
	case a := <-addrCh:
		return "http://" + a
	case err := <-done:
		t.Fatalf("serve exited early: %v\n%s", err, logs.String())
	case <-time.After(60 * time.Second):
		t.Fatal("server did not start")
	}
	return ""
}

func getBody(t *testing.T, url string) (int, []byte) {
	t.Helper()
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, url, nil)
	resp, err := (&http.Client{Timeout: 5 * time.Second}).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, b
}

// TestHR194_ServerPublishesItsEvidenceKeys: a running server publishes the
// receipts, checkpoints, anchors and evidence-pack keys it created, in a
// document that pins as a trust file, and an empty revocation list.
func TestHR194_ServerPublishesItsEvidenceKeys(t *testing.T) {
	d := dbtest.New(t)
	base := serveForTest(t, testConfig(t, d, RoleAPI))
	code, b := getBody(t, base+keydocs.EvidenceKeysPath)
	if code != http.StatusOK {
		t.Fatalf("evidence-keys.json = %d %s", code, b)
	}
	trust, err := bundle.ParseEvidenceKeys(b)
	if err != nil {
		t.Fatal(err)
	}
	if trust.LogOrigin != "127.0.0.1:8080" || trust.Issuer != "http://127.0.0.1:8080" {
		t.Fatalf("log origin %q, issuer %q: want both from auth.public_url", trust.LogOrigin, trust.Issuer)
	}
	count := map[string]int{}
	for _, k := range trust.Keys {
		if k.State != bundle.StateActive {
			t.Errorf("key %s is %s", k.KID, k.State)
		}
		count[k.Purpose]++
	}
	want := map[string]int{
		bundle.PurposeReceipts: 1, bundle.PurposeCheckpoints: 1, bundle.PurposeAnchors: 1, bundle.PurposeEvidencePacks: 1,
	}
	if len(count) != len(want) {
		t.Fatalf("published purposes %v, want %v (no ML-DSA-65 key without co-signing)", count, want)
	}
	for p, n := range want {
		if count[p] != n {
			t.Errorf("%s: %d keys, want %d", p, count[p], n)
		}
	}
	code, b = getBody(t, base+keydocs.RevokedKeysPath)
	var revoked struct {
		Format string `json:"format"`
		Keys   []any  `json:"keys"`
	}
	if code != http.StatusOK || json.Unmarshal(b, &revoked) != nil || revoked.Format != keydocs.RevokedKeysFormat || len(revoked.Keys) != 0 {
		t.Fatalf("revoked-keys.json = %d %s", code, b)
	}
}

// TestIntMLDSACosignNeedsEnterprise: without an Enterprise licence the
// server refuses to start with co-signing on.
func TestIntMLDSACosignNeedsEnterprise(t *testing.T) {
	d := dbtest.New(t)
	cfgPath := testConfig(t, d, RoleAPI, func(c map[string]any) {
		c["evidence"] = map[string]any{"mldsa_cosign": true}
	})
	var logs bytes.Buffer
	err := cmdServe(context.Background(), []string{"--config", cfgPath}, &logs, noEnv, nil)
	if !errors.Is(err, errMLDSAEdition) {
		t.Fatalf("serve with co-signing on a Community licence: %v", err)
	}
}
