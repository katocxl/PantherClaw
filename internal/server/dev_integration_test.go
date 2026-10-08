// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package server

import (
	"bytes"
	"context"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect/v2"
	"connectrpc.com/connect/v2/connecthttp"

	"github.com/katocxl/pantherclaw/internal/actionir"
	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/db/dbtest"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// serve starts cmdServe with cfgPath and returns the API base URL.
func serve(t *testing.T, cfgPath string) string {
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
			t.Error("graceful shutdown did not finish")
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

var seededOrg = regexp.MustCompile(`seeded org ([0-9a-f-]{36}) `)

// seed runs `dev seed` and returns the org and the token file.
func seed(t *testing.T, cfgPath, limit string) (ids.OrgID, string) {
	t.Helper()
	tokenFile := filepath.Join(t.TempDir(), "gateway-token")
	var out, errb bytes.Buffer
	args := []string{"dev", "seed", "--config", cfgPath, "--org-name", "acme", "--budget-limit", limit, "--token-out", tokenFile}
	if code := Run(context.Background(), args, &out, &errb, noEnv); code != 0 {
		t.Fatalf("dev seed: %d %s", code, errb.String())
	}
	m := seededOrg.FindStringSubmatch(out.String())
	if m == nil {
		t.Fatalf("dev seed output %q", out.String())
	}
	if code := Run(context.Background(), args, &out, &errb, noEnv); code == 0 {
		t.Fatal("dev seed overwrote an existing token file")
	}
	return ids.MustParse[ids.Org](m[1]), tokenFile
}

func refund(t *testing.T, org ids.OrgID, amount string) []byte {
	t.Helper()
	p, err := actionir.Encode(actionir.ActionIR{
		V: 1, Org: org.String(), Env: "01920000-0000-7000-8000-00000000000e", RunID: ids.NewV7().String(), ActionID: ids.NewV7().String(),
		AgentInstance: "01920000-0000-7000-8000-0000000000c1", Operation: actionir.OpRefundCreate,
		Definition: actionir.Definition{
			Package: "pc.mock-payments", Version: "1.0.0",
			Digest: "sha256:0000000000000000000000000000000000000000000000000000000000000001",
		},
		Channel: "http", Route: "payments-refund", Target: actionir.Target{Type: "payments.charge", ID: "ch_1", Account: "acct_1"},
		Params: jsontext.Value(`{"amount":{"value":"` + amount + `","currency":"USD"},"reason":"duplicate"}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	return p.Canonical
}

func authorize(client pantherclawv1connect.AuthorityServiceClient, token string, action []byte) (*pantherclawv1.AuthorizeResponse, error) {
	ctx, info := connect.NewClientContext(context.Background())
	if token != "" {
		info.RequestHeader().Set("Authorization", "Bearer "+token)
	}
	return client.Authorize(ctx, &pantherclawv1.AuthorizeRequest{ActionIr: action})
}

func TestIntDevGatewayAuthorizeAndSweep(t *testing.T) {
	d := dbtest.New(t)
	org, tokenFile := seed(t, testConfig(t, d, RoleAll), "100.00")
	token, err := os.ReadFile(tokenFile)
	if err != nil {
		t.Fatal(err)
	}
	cfgPath := testConfig(t, d, RoleAll, func(c map[string]any) {
		c["dev_gateway"] = map[string]any{"enabled": true, "org": org.String(), "gateway_id": "gw-dev-1", "token_file": tokenFile}
		c["authority"] = map[string]any{"permit_ttl": "1s"}
	})
	base := serve(t, cfgPath)
	client := pantherclawv1connect.NewAuthorityServiceClient(connect.NewClient(connecthttp.NewTransport(&http.Client{Timeout: 10 * time.Second}, base)))

	// No or a wrong credential: refused before any decision.
	for _, tok := range []string{"", "not-the-token-not-the-token-not-the"} {
		if _, err := authorize(client, tok, refund(t, org, "30.00")); connect.CodeOf(err) != connect.CodeUnauthenticated {
			t.Fatalf("token %q: %v, want Unauthenticated", tok, err)
		}
	}
	tok := strings.TrimSpace(string(token))
	res, err := authorize(client, tok, refund(t, org, "30.00"))
	if err != nil || res.GetDecision() != pantherclawv1.Decision_DECISION_ALLOW || res.GetPermit() == "" {
		t.Fatalf("Authorize = %v, %v", res, err)
	}
	// Another org's action is denied: the org comes from the credential.
	other, err := authorize(client, tok, refund(t, ids.New[ids.Org](), "30.00"))
	if err != nil || other.GetDecision() != pantherclawv1.Decision_DECISION_DENY {
		t.Fatalf("cross-org Authorize = %v, %v", other, err)
	}

	// The worker's sweeper releases the undispatched permit after its 1s TTL.
	p := d.AppPool(t)
	deadline := time.Now().Add(30 * time.Second)
	for {
		var state string
		var free bool
		err := p.InTenantTx(context.Background(), org, func(ctx context.Context, tx db.TenantTx) error {
			if err := tx.QueryRow(ctx, "SELECT state FROM pc.permits WHERE transaction_id = $1", res.GetTransactionId()).Scan(&state); err != nil {
				return err
			}
			return tx.QueryRow(ctx, "SELECT reserved = 0 AND reserved_count = 0 FROM pc.budgets").Scan(&free)
		})
		if err != nil {
			t.Fatal(err)
		}
		if state == "RELEASED" {
			if !free {
				t.Fatal("released permit left its reservation")
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("permit still %s after 30s", state)
		}
		time.Sleep(200 * time.Millisecond)
	}
}

func TestIntAuthorityRefusedWithoutDevGateway(t *testing.T) {
	d := dbtest.New(t)
	base := serve(t, testConfig(t, d, RoleAPI))
	client := pantherclawv1connect.NewAuthorityServiceClient(connect.NewClient(connecthttp.NewTransport(&http.Client{Timeout: 10 * time.Second}, base)))
	_, err := authorize(client, "any-token-any-token-any-token-any", refund(t, ids.New[ids.Org](), "1.00"))
	var ce *connect.Error
	if !errors.As(err, &ce) || ce.Code() != connect.CodeUnauthenticated {
		t.Fatalf("Authorize without a dev gateway = %v, want Unauthenticated", err)
	}
}

func TestIntDevSeedAudits(t *testing.T) {
	d := dbtest.New(t)
	org, _ := seed(t, testConfig(t, d, RoleAPI), "50.00")
	var kinds []string
	err := d.AppPool(t).InTenantTx(context.Background(), org, func(ctx context.Context, tx db.TenantTx) error {
		rows, err := tx.Query(ctx, "SELECT kind, body FROM pc.ledger_entries ORDER BY id")
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var kind string
			var body []byte
			if err := rows.Scan(&kind, &body); err != nil {
				return err
			}
			var v map[string]any
			if err := json.Unmarshal(body, &v); err != nil {
				return err
			}
			kinds = append(kinds, kind)
		}
		return rows.Err()
	})
	if err != nil || len(kinds) != 1 || kinds[0] != "audit.dev.org_seeded" {
		t.Fatalf("org ledger = %v, %v", kinds, err)
	}
}
