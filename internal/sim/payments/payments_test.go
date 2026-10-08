// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package payments

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
)

func post(t *testing.T, url, key, body string) (int, string, http.Header) {
	t.Helper()
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, url+"/v1/refunds", strings.NewReader(body))
	if key != "" {
		req.Header.Set("Idempotency-Key", key)
	}
	c := &http.Client{Timeout: 2 * time.Second}
	resp, err := c.Do(req)
	if err != nil {
		return 0, err.Error(), nil
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b), resp.Header
}

const okBody = `{"charge":"ch_1","amount":"30.00","currency":"USD","reason":"duplicate"}`

func TestRefundAndIdempotency(t *testing.T) {
	s := New(Faults{}, pclog.Discard())
	ts := httptest.NewServer(s.Handler())
	defer ts.Close()
	code, body, h := post(t, ts.URL, "txn-0001-key", okBody)
	if code != http.StatusOK || !strings.Contains(body, `"simulated":true`) || h.Get("Simulated") != "true" {
		t.Fatalf("refund = %d %s", code, body)
	}
	// A retry with the same key and body is a replay, not a second refund.
	code2, body2, h2 := post(t, ts.URL, "txn-0001-key", okBody)
	if code2 != http.StatusOK || body2 != body || h2.Get("Idempotent-Replayed") != "true" {
		t.Fatalf("replay = %d %s", code2, body2)
	}
	// Same key, different request: refused.
	if code, _, _ := post(t, ts.URL, "txn-0001-key", strings.Replace(okBody, "30.00", "90.00", 1)); code != http.StatusConflict {
		t.Fatalf("key reuse with another body = %d", code)
	}
	if st := s.Stats(); st.Refunds != 1 || st.Total != "30" || st.Replays != 1 {
		t.Fatalf("stats = %+v", st)
	}
}

func TestRejectsBadRequests(t *testing.T) {
	ts := httptest.NewServer(New(Faults{}, pclog.Discard()).Handler())
	defer ts.Close()
	for name, tc := range map[string][2]string{
		"no key":        {"", okBody},
		"short key":     {"k", okBody},
		"unknown field": {"txn-0002-key", strings.Replace(okBody, `}`, `,"to":"acct_x"}`, 1)},
		"number amount": {"txn-0003-key", strings.Replace(okBody, `"30.00"`, `30.00`, 1)},
		"bad charge":    {"txn-0004-key", strings.Replace(okBody, "ch_1", "../ch", 1)},
		"zero amount":   {"txn-0005-key", strings.Replace(okBody, "30.00", "0", 1)},
		"unknown ccy":   {"txn-0006-key", strings.Replace(okBody, "USD", "XYZ", 1)},
	} {
		if code, _, _ := post(t, ts.URL, tc[0], tc[1]); code != http.StatusBadRequest {
			t.Errorf("%s: %d, want 400", name, code)
		}
	}
}

func TestFaultInjection(t *testing.T) {
	s := New(Faults{DeclineRate: 1}, pclog.Discard())
	ts := httptest.NewServer(s.Handler())
	defer ts.Close()
	if code, _, _ := post(t, ts.URL, "txn-0007-key", okBody); code != http.StatusPaymentRequired {
		t.Fatalf("decline = %d", code)
	}
	if s.Stats().Refunds != 0 {
		t.Fatal("declined refund recorded")
	}
	hang := New(Faults{HangRate: 1, HangFor: time.Hour}, pclog.Discard())
	hs := httptest.NewServer(hang.Handler())
	defer hs.Close()
	if code, _, _ := post(t, hs.URL, "txn-0008-key", okBody); code != 0 {
		t.Fatalf("hang returned %d, want client timeout", code)
	}
	if hang.Stats().Refunds != 0 {
		t.Fatal("hung request recorded a refund")
	}
	// A hang that ends before the client gives up drops the connection; it
	// must never look like a successful (empty 200) response.
	short := httptest.NewServer(New(Faults{HangRate: 1, HangFor: 50 * time.Millisecond}, pclog.Discard()).Handler())
	defer short.Close()
	if code, _, _ := post(t, short.URL, "txn-0009-key", okBody); code != 0 {
		t.Fatalf("ended hang returned %d, want a dropped connection", code)
	}
	if chance(0) || !chance(1) {
		t.Fatal("chance bounds wrong")
	}
}
