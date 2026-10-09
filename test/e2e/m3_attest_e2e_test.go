// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package e2e

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json/v2"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"connectrpc.com/connect/v2"

	aapp "github.com/katocxl/pantherclaw/internal/agents/app"
	adomain "github.com/katocxl/pantherclaw/internal/agents/domain"
	billing "github.com/katocxl/pantherclaw/internal/billing/domain"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	"github.com/katocxl/pantherclaw/internal/identity/adapters/issuerkeys"
	"github.com/katocxl/pantherclaw/internal/identity/adapters/kube"
	"github.com/katocxl/pantherclaw/internal/identity/adapters/workloadrpc"
	iapp "github.com/katocxl/pantherclaw/internal/identity/app"
	"github.com/katocxl/pantherclaw/internal/identity/issuers"
	"github.com/katocxl/pantherclaw/internal/pclaw"
	"github.com/katocxl/pantherclaw/internal/platform/clock"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/db/dbtest"
	"github.com/katocxl/pantherclaw/internal/platform/httpx"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/keys"
	"github.com/katocxl/pantherclaw/internal/platform/rpc"
	runsapp "github.com/katocxl/pantherclaw/internal/runs/app"
	tenancy "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

type unlimited struct{}

func (unlimited) Current(context.Context) (billing.Entitlements, error) {
	e := billing.CommunityEntitlements()
	e.Edition, e.Limits.MaxAgents = billing.Business, billing.Unlimited
	return e, nil
}

const (
	repoRef = "acme/agent/.github/workflows/agent.yml@refs/heads/main"
	saUID   = "6f1d2c3b-4a59-4e2b-9c1d-0a1b2c3d4e5f"
)

// actionsIssuer is an in-process GitHub Actions OIDC issuer with a test
// key: discovery, JWKS and the runtime's token endpoint.
type actionsIssuer struct {
	srv   *httptest.Server
	key   *rsa.PrivateKey
	mu    sync.Mutex
	event string
}

func newActionsIssuer(t *testing.T) *actionsIssuer {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	is := &actionsIssuer{key: key, event: "push"}
	enc := base64.RawURLEncoding.EncodeToString
	mux := http.NewServeMux()
	is.srv = httptest.NewTLSServer(mux)
	t.Cleanup(is.srv.Close)
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"issuer":"` + is.srv.URL + `","jwks_uri":"` + is.srv.URL + `/jwks"}`))
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"keys":[{"kty":"RSA","kid":"k1","use":"sig","alg":"RS256","n":"` + enc(key.N.Bytes()) +
			`","e":"` + enc(big.NewInt(int64(key.E)).Bytes()) + `"}]}`))
	})
	// The Actions runtime: a token for the requested audience.
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer runtime-token" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		is.mu.Lock()
		event := is.event
		is.mu.Unlock()
		ref := "refs/heads/main"
		if event == "pull_request" {
			ref = "refs/pull/7/merge"
		}
		now := time.Now()
		claims, _ := json.Marshal(map[string]any{
			"iss": issuers.GitHubIssuer, "aud": r.URL.Query().Get("audience"), "jti": ids.NewV7().String(),
			"repository_id": "123456", "repository_owner_id": "7890", "ref": ref, "ref_protected": "true", "event_name": event,
			"workflow_ref": repoRef, "iat": now.Unix(), "exp": now.Add(10 * time.Minute).Unix(),
		})
		signing := enc([]byte(`{"alg":"RS256","kid":"k1","typ":"JWT"}`)) + "." + enc(claims)
		sum := sha256.Sum256([]byte(signing))
		sig, _ := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, sum[:])
		_, _ = w.Write([]byte(`{"value":"` + signing + "." + enc(sig) + `"}`))
	})
	return is
}

// fakeCluster is a Kubernetes API server: TokenReview accepts token and
// binds it to a running pod of agents/coder.
func fakeCluster(t *testing.T, token string) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("POST /apis/authentication.k8s.io/v1/tokenreviews", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Spec struct {
				Token     string   `json:"token"`
				Audiences []string `json:"audiences"`
			} `json:"spec"`
		}
		_ = json.UnmarshalRead(r.Body, &req)
		if req.Spec.Token != token {
			_, _ = w.Write([]byte(`{"status":{"authenticated":false}}`))
			return
		}
		aud, _ := json.Marshal(req.Spec.Audiences)
		_, _ = w.Write([]byte(`{"status":{"authenticated":true,"audiences":` + string(aud) + `,"user":{
			"username":"system:serviceaccount:agents:coder","uid":"` + saUID + `",
			"extra":{"authentication.kubernetes.io/pod-name":["coder-1"],"authentication.kubernetes.io/pod-uid":["pod-uid-1"]}}}}`))
	})
	mux.HandleFunc("GET /api/v1/namespaces/agents/pods/coder-1", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"metadata":{"namespace":"agents","name":"coder-1","uid":"pod-uid-1"},"status":{"phase":"Running",
			"containerStatuses":[{"imageID":"ghcr.io/acme/agent@sha256:` + strings.Repeat("a", 64) + `"}]}}`))
	})
	srv := httptest.NewTLSServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func pemFile(t *testing.T, dir, name string, cert *x509.Certificate) string {
	t.Helper()
	return writeFile(t, dir, name, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}))
}

// TestE2E_M3_AttestedAutoAdmission: a CI job auto-admits through the
// GitHub preset (an in-process issuer with test keys, verified by the real
// key fetcher), a pod through the Kubernetes preset (a fake API server,
// called by the real cluster client), both with `pclaw workload`; a
// pull-request token is refused.
func TestE2E_M3_AttestedAutoAdmission(t *testing.T) {
	ctx := context.Background()
	d := dbtest.New(t)
	pool := d.AppPool(t)
	reg := keys.NewRegistry()
	for _, p := range keys.Purposes() {
		k, err := keys.GenerateSigningKey(p)
		if err != nil {
			t.Fatal(err)
		}
		if err := reg.Put(k); err != nil {
			t.Fatal(err)
		}
	}
	org, team, env, owner := ids.New[ids.Org](), ids.NewV7(), ids.NewV7(), ids.NewV7()
	if err := pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		for _, q := range []struct {
			sql  string
			args []any
		}{
			{"INSERT INTO pc.orgs (id, name) VALUES ($1, 'acme')", []any{org}},
			{"INSERT INTO pc.teams (org_id, id, slug, name) VALUES ($1, $2, 'ci', 'CI')", []any{org, team}},
			{"INSERT INTO pc.environments (org_id, id, team_id, slug, name, kind) VALUES ($1, $2, $3, 'ci', 'CI', 'DEVELOPMENT')", []any{org, env, team}},
			{"INSERT INTO pc.users (org_id, id, issuer, subject) VALUES ($1, $2, 'https://idp.test', 'alice')", []any{org, owner}},
		} {
			if _, err := tx.Exec(ctx, q.sql, q.args...); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	// The real adapters, pointed at the test issuer and the fake cluster.
	actions := newActionsIssuer(t)
	k8sToken := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256"}`)) + "." +
		base64.RawURLEncoding.EncodeToString([]byte(`{"aud":["pantherclaw:`+org.String()+`"],"iat":`+
			itoa(time.Now().Unix())+`,"exp":`+itoa(time.Now().Add(50*time.Minute).Unix())+`,"jti":"pod-token-1"}`)) + ".sig"
	cluster := fakeCluster(t, k8sToken)
	dir := t.TempDir()
	pool509 := x509.NewCertPool()
	pool509.AddCert(actions.srv.Certificate())
	gh, err := issuerkeys.New(httpx.NewEgressClient(httpx.EgressConfig{
		RootCAs: pool509, AllowedPrefixes: []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")},
	}), actions.srv.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	clusters, err := kube.NewDirectory([]kube.ClusterConfig{{
		Name: "prod", APIServer: cluster.URL, CAFile: pemFile(t, dir, "ca.pem", cluster.Certificate()),
		TokenFile: writeFile(t, dir, "reviewer", []byte("reviewer-token")), AllowedPrefixes: []string{"127.0.0.0/8"},
		Orgs: []string{org.String()},
	}})
	if err != nil {
		t.Fatal(err)
	}
	kc, err := kube.NewClient(clusters, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	ws := httptest.NewUnstartedServer(nil)
	public := "http://" + ws.Listener.Addr().String()
	svc := iapp.New(pool, reg, public, clock.System{}).WithAttestors(iapp.Attestors{GitHub: gh, Kube: kc, Clusters: clusters})
	s, err := rpc.NewServer(rpc.Options{Authenticate: func(ctx context.Context, _ *connect.CallInfo, _ connect.Spec) (context.Context, error) {
		return ctx, nil // WorkloadService authenticates with PAP/1 itself
	}})
	if err != nil {
		t.Fatal(err)
	}
	pantherclawv1connect.RegisterWorkloadServiceHandler(s, workloadrpc.NewWorkload(svc, runsapp.New(pool), public, clock.System{}))
	inner := http.NewServeMux()
	rpc.Mount(inner, s)
	ws.Config.Handler = workloadrpc.RawBody(inner, nil)
	ws.Start()
	t.Cleanup(ws.Close)

	// Agents and auto-admitting issuer entries, activated by an Identity Publisher.
	person := func(role td.RoleName, scope td.Scope) context.Context {
		return tenancy.WithCaller(ctx, tenancy.Caller{Subject: td.Subject{
			Org: org, Principal: td.PrincipalRef{Kind: td.KindUser, ID: owner}, Bindings: []td.Binding{{Role: role, Scope: scope}},
		}})
	}
	inv := aapp.NewInventory(pool, unlimited{})
	newAgent := func(name string, c adomain.ExecutionContext) ids.UUID {
		a, err := inv.Create(person(td.RoleAgentOwner, td.Scope{Type: td.ScopeTeam, ID: team}), adomain.Details{
			Name: name, TeamID: team, EnvironmentID: env, OwnerUserID: owner, Context: c,
		})
		if err != nil {
			t.Fatal(err)
		}
		return a.ID
	}
	orgScope := td.Scope{Type: td.ScopeOrg, ID: org.UUID()}
	activate := func(agent ids.UUID, b iapp.Binding) {
		r, err := svc.ProposeIssuer(person(td.RoleOrgAdmin, orgScope), iapp.ProposeInput{AgentID: agent, Binding: b, AutoAdmit: true, Reason: "e2e"}, clusters)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := svc.ActivateIssuer(person(td.RoleIdentityPublisher, orgScope), r.EntryID, r.Revision, false); err != nil {
			t.Fatal(err)
		}
	}
	activate(newAgent("ci-bot", adomain.ContextCI), iapp.Binding{GitHub: &issuers.GitHubBinding{
		RepositoryID: "123456", RepositoryOwnerID: "7890", JobType: issuers.JobWorkflow, WorkflowRefs: []string{repoRef},
	}})
	activate(newAgent("pod-bot", adomain.ContextKubernetes), iapp.Binding{Kubernetes: &issuers.KubernetesBinding{
		Cluster: "prod", Namespace: "agents", ServiceAccountName: "coder", ServiceAccountUID: saUID,
		ImageRepositories: []string{"ghcr.io/acme/agent"},
	}})

	// The workloads, with pclaw. Its HTTP client trusts the test issuer.
	client := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool509, MinVersion: tls.VersionTLS12}}}
	cli := func(env map[string]string, args ...string) (int, string, string) {
		var out, errb bytes.Buffer
		code := pclaw.Run(ctx, args, &out, &errb, func(k string) (string, bool) { v, ok := env[k]; return v, ok }, pclaw.Options{HTTPClient: client})
		return code, out.String(), errb.String()
	}
	actionsEnv := map[string]string{"ACTIONS_ID_TOKEN_REQUEST_URL": actions.srv.URL + "/token?api-version=2.0", "ACTIONS_ID_TOKEN_REQUEST_TOKEN": "runtime-token"}
	ciKey := filepath.Join(dir, "ci.json")
	if code, _, e := cli(nil, "workload", "init", "--key-file", ciKey); code != 0 {
		t.Fatal(e)
	}
	if code, o, e := cli(actionsEnv, "workload", "enroll", "--key-file", ciKey, "--server", public, "--github", "--org", org.String()); code != 0 ||
		!strings.Contains(o, "admitted") || !strings.Contains(o, "(L2)") {
		t.Fatalf("GitHub enroll: %d %s %s", code, o, e)
	}
	if code, o, e := cli(actionsEnv, "workload", "token", "--key-file", ciKey, "--github"); code != 0 || attLevel(t, strings.TrimSpace(o)) != 2 {
		t.Fatalf("GitHub re-attested token: %d %s %s", code, o, e)
	}
	actions.mu.Lock()
	actions.event = "pull_request"
	actions.mu.Unlock()
	prKey := filepath.Join(dir, "pr.json")
	_, _, _ = cli(nil, "workload", "init", "--key-file", prKey)
	if code, _, e := cli(actionsEnv, "workload", "enroll", "--key-file", prKey, "--server", public, "--github", "--org", org.String()); code != 1 ||
		!strings.Contains(e, "attestation_insufficient") {
		t.Fatalf("pull-request token: %d %s", code, e)
	}

	podKey, tokenFile := filepath.Join(dir, "pod.json"), writeFile(t, dir, "projected", []byte(k8sToken))
	_, _, _ = cli(nil, "workload", "init", "--key-file", podKey)
	if code, o, e := cli(nil, "workload", "enroll", "--key-file", podKey, "--server", public, "--kubernetes-token", tokenFile, "--org", org.String()); code != 0 ||
		!strings.Contains(o, "admitted") {
		t.Fatalf("Kubernetes enroll: %d %s %s", code, o, e)
	}
	var digest string
	if err := pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		return tx.QueryRow(ctx, "SELECT release_state || ' ' || release_digest FROM pc.agent_instances WHERE org_id = $1 AND enrolled_via = 'attestation' AND release_digest IS NOT NULL", org).Scan(&digest)
	}); err != nil || digest != "attested sha256:"+strings.Repeat("a", 64) {
		t.Fatalf("pod release %q, %v", digest, err)
	}
	if _, err := os.Stat(podKey); err != nil {
		t.Fatal(err)
	}
}

func itoa(n int64) string { return big.NewInt(n).String() }

// attLevel reads pap.att_lvl from a workload token (unverified: the
// server issued it in this test).
func attLevel(t *testing.T, token string) int {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return 0
	}
	b, _ := base64.RawURLEncoding.DecodeString(parts[1])
	var c struct {
		PAP struct {
			Level int `json:"att_lvl"`
		} `json:"pap"`
	}
	_ = json.Unmarshal(b, &c)
	return c.PAP.Level
}
