// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package server

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"net"
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
	"github.com/katocxl/pantherclaw/internal/identity/pap"
	"github.com/katocxl/pantherclaw/internal/identity/workloadclient"
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

// seed runs `dev seed` and returns the org, the gateway token file and the
// workload key file.
func seed(t *testing.T, cfgPath, limit string) (ids.OrgID, string, string) {
	t.Helper()
	dir := t.TempDir()
	tokenFile, keyFile := filepath.Join(dir, "gateway-token"), filepath.Join(dir, "workload.json")
	var out, errb bytes.Buffer
	args := []string{
		"dev", "seed", "--config", cfgPath, "--org-name", "acme", "--budget-limit", limit, "--token-out", tokenFile,
		"--workload-out", keyFile,
	}
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
	return ids.MustParse[ids.Org](m[1]), tokenFile, keyFile
}

// workload is the seeded PAP/1 workload, acting through a gateway.
type workload struct {
	kf    workloadclient.KeyFile
	key   ed25519.PrivateKey
	inst  pap.Instance
	env   string
	token string
}

// seededWorkload reads the key file and gets a workload token from base.
func seededWorkload(t *testing.T, base, keyFile string) workload {
	t.Helper()
	kf, err := workloadclient.ReadKeyFile(keyFile)
	if err != nil {
		t.Fatal(err)
	}
	key, _ := kf.Key()
	inst, err := pap.ParseInstance(kf.Identifier)
	if err != nil {
		t.Fatal(err)
	}
	wc := pantherclawv1connect.NewWorkloadServiceClient(connect.NewClient(connecthttp.NewTransport(
		&http.Client{Timeout: 10 * time.Second, Transport: &workloadclient.Transport{Key: key}}, base)))
	res, err := wc.IssueToken(context.Background(), &pantherclawv1.IssueTokenRequest{Identifier: kf.Identifier})
	if err != nil {
		t.Fatalf("IssueToken: %v", err)
	}
	payload, _ := base64.RawURLEncoding.DecodeString(strings.Split(res.GetWorkloadToken(), ".")[1])
	var claims struct {
		PAP struct {
			Env string `json:"env"`
		} `json:"pap"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatal(err)
	}
	return workload{kf: kf, key: key, inst: inst, env: claims.PAP.Env, token: res.GetWorkloadToken()}
}

func refund(t *testing.T, org ids.OrgID, wl workload, amount string) []byte {
	t.Helper()
	p, err := actionir.Encode(actionir.ActionIR{
		V: 1, Org: org.String(), Env: wl.env, RunID: wl.kf.RunID, ActionID: ids.NewV7().String(),
		AgentInstance: wl.inst.Instance.String(), Operation: actionir.OpRefundCreate,
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

// creds are the PAP/1 credentials of one workload request, as a gateway
// would forward them.
func (wl workload) creds(t *testing.T, nonce string) *pantherclawv1.WorkloadCredentials {
	t.Helper()
	const url = "http://127.0.0.1:8090/v1/refunds"
	body := []byte(`{"charge":"ch_1","amount":"30.00","currency":"USD"}`)
	proof, err := pap.NewProof(wl.key, pap.ProofParams{Method: "POST", URL: url, Body: body, Token: wl.token, Nonce: nonce, Now: time.Now()})
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(body)
	return &pantherclawv1.WorkloadCredentials{WorkloadToken: wl.token, Proof: proof, BodySha256: sum[:], Htm: "POST", Htu: url}
}

func gatewayCtx(token string) context.Context {
	ctx, info := connect.NewClientContext(context.Background())
	if token != "" {
		info.RequestHeader().Set("Authorization", "Bearer "+token)
	}
	return ctx
}

func authorize(client pantherclawv1connect.AuthorityServiceClient, token string, action []byte, creds *pantherclawv1.WorkloadCredentials) (*pantherclawv1.AuthorizeResponse, error) {
	return client.Authorize(gatewayCtx(token), &pantherclawv1.AuthorizeRequest{ActionIr: action, Workload: creds})
}

// publicAt serves on addr and makes it the public URL, so workload proofs
// name the address they are sent to.
func publicAt(addr string) func(map[string]any) {
	return func(c map[string]any) {
		c["http"] = map[string]any{"addr": addr}
		c["auth"] = map[string]any{"public_url": "http://" + addr}
	}
}

func freeAddr(t *testing.T) string {
	t.Helper()
	var lc net.ListenConfig
	ln, err := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	return ln.Addr().String()
}

func TestIntDevGatewayAuthorizeAndSweep(t *testing.T) {
	d := dbtest.New(t)
	at := publicAt(freeAddr(t))
	org, tokenFile, keyFile := seed(t, testConfig(t, d, RoleAll, at), "100.00")
	token, err := os.ReadFile(tokenFile)
	if err != nil {
		t.Fatal(err)
	}
	cfgPath := testConfig(t, d, RoleAll, at, func(c map[string]any) {
		c["dev_gateway"] = map[string]any{"enabled": true, "org": org.String(), "gateway_id": "gw-dev-1", "token_file": tokenFile}
		c["authority"] = map[string]any{"permit_ttl": "1s"}
	})
	base := serve(t, cfgPath)
	client := pantherclawv1connect.NewAuthorityServiceClient(connect.NewClient(connecthttp.NewTransport(&http.Client{Timeout: 10 * time.Second}, base)))
	wl := seededWorkload(t, base, keyFile)
	tok := strings.TrimSpace(string(token))
	nonce, err := client.GetNonce(gatewayCtx(tok), &pantherclawv1.GetNonceRequest{})
	if err != nil {
		t.Fatal(err)
	}

	// No or a wrong credential: refused before any decision.
	for _, gt := range []string{"", "not-the-token-not-the-token-not-the"} {
		if _, err := authorize(client, gt, refund(t, org, wl, "30.00"), wl.creds(t, nonce.GetNonce())); connect.CodeOf(err) != connect.CodeUnauthenticated {
			t.Fatalf("token %q: %v, want Unauthenticated", gt, err)
		}
	}
	// Without the workload's credentials nothing is authorized (HR-021).
	if res, err := authorize(client, tok, refund(t, org, wl, "30.00"), nil); err != nil ||
		res.GetDecision() != pantherclawv1.Decision_DECISION_CANNOT_AUTHORIZE {
		t.Fatalf("Authorize without workload credentials = %v, %v", res, err)
	}
	res, err := authorize(client, tok, refund(t, org, wl, "30.00"), wl.creds(t, nonce.GetNonce()))
	if err != nil || res.GetDecision() != pantherclawv1.Decision_DECISION_ALLOW || res.GetPermit() == "" {
		t.Fatalf("Authorize = %v, %v", res, err)
	}
	// Another org's action is denied: the org comes from the credential.
	other, err := authorize(client, tok, refund(t, ids.New[ids.Org](), wl, "30.00"), wl.creds(t, nonce.GetNonce()))
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
	_, err := client.Authorize(gatewayCtx("any-token-any-token-any-token-any"), &pantherclawv1.AuthorizeRequest{ActionIr: []byte(`{}`)})
	var ce *connect.Error
	if !errors.As(err, &ce) || ce.Code() != connect.CodeUnauthenticated {
		t.Fatalf("Authorize without a dev gateway = %v, want Unauthenticated", err)
	}
}

func TestIntDevSeedAudits(t *testing.T) {
	d := dbtest.New(t)
	org, _, _ := seed(t, testConfig(t, d, RoleAPI), "50.00")
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
	if err != nil || len(kinds) != 2 || kinds[0] != "audit.dev.org_seeded" || kinds[1] != "audit.dev.workload_seeded" {
		t.Fatalf("org ledger = %v, %v", kinds, err)
	}
}
