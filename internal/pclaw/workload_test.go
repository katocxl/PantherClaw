// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pclaw

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"connectrpc.com/connect/v2"
	"connectrpc.com/connect/v2/connecthttp"

	"github.com/katocxl/pantherclaw/internal/authn/credential"
	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	"github.com/katocxl/pantherclaw/internal/identity/workloadclient"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// fakeWorkloadService records what the workload commands send.
type fakeWorkloadService struct {
	pantherclawv1connect.UnimplementedWorkloadServiceHandler
	mu     sync.Mutex
	enroll *pantherclawv1.EnrollRequest
	token  *pantherclawv1.IssueTokenRequest
	proofs int
	org    ids.OrgID
}

func (f *fakeWorkloadService) Enroll(ctx context.Context, req *pantherclawv1.EnrollRequest) (*pantherclawv1.EnrollResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.enroll = f.count(ctx, req).(*pantherclawv1.EnrollRequest)
	inst := ids.NewV7()
	res := &pantherclawv1.EnrollResponse{
		InstanceId: inst.String(), Identifier: "pc:org/" + f.org.String() + "/agent/" + ids.NewV7().String() + "/inst/" + inst.String(),
		State: pantherclawv1.InstanceState_INSTANCE_STATE_PENDING_ADMISSION, Fingerprint: "fp-1",
	}
	if req.GetAttestation() != nil && req.GetEnrollmentToken() == "" {
		res.State, res.AttestationLevel = pantherclawv1.InstanceState_INSTANCE_STATE_ADMITTED, 2
	}
	return res, nil
}

func (f *fakeWorkloadService) IssueToken(ctx context.Context, req *pantherclawv1.IssueTokenRequest) (*pantherclawv1.IssueTokenResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.token = f.count(ctx, req).(*pantherclawv1.IssueTokenRequest)
	return &pantherclawv1.IssueTokenResponse{WorkloadToken: "wt-1", AttestationLevel: 1}, nil
}

// count records that the request carried a PAP-Proof (the server verifies it).
func (f *fakeWorkloadService) count(ctx context.Context, req any) any {
	if info, ok := connect.CallInfoForServerContext(ctx); ok && info.RequestHeader().Get("PAP-Proof") != "" {
		f.proofs++
	}
	return req
}

func workloadServer(t *testing.T, f *fakeWorkloadService) string {
	t.Helper()
	cs := connect.NewServer()
	pantherclawv1connect.RegisterWorkloadServiceHandler(cs, f)
	mux := http.NewServeMux()
	connecthttp.Mount(mux, cs)
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)
	return ts.URL
}

// TestWorkloadEnrollWithAnEnrollmentToken: init writes a key, enroll sends
// its public key and the owner's token with a proof, prints what the owner
// must check, and records the identifier; token then works from the file.
func TestWorkloadEnrollWithAnEnrollmentToken(t *testing.T) {
	f := &fakeWorkloadService{org: ids.New[ids.Org]()}
	server := workloadServer(t, f)
	dir := t.TempDir()
	keyFile, tokenFile := filepath.Join(dir, "workload.json"), filepath.Join(dir, "enroll")
	tok, err := credential.New(credential.EnrollmentToken, "", f.org)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(tokenFile, []byte(tok.Reveal()+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	env := envOf(nil)
	if code, out, errs := run(t, env, "workload", "init", "--key-file", keyFile); code != 0 || !strings.Contains(out, "fingerprint") {
		t.Fatalf("init = %d %q %q", code, out, errs)
	}
	if code, _, _ := run(t, env, "workload", "init", "--key-file", keyFile); code != 1 {
		t.Fatal("init overwrote an existing key file")
	}
	code, out, errs := run(t, env, "workload", "enroll", "--key-file", keyFile, "--server", server, "--enrollment-token-file", tokenFile)
	if code != 0 || !strings.Contains(out, "pclaw instance admit") || !strings.Contains(out, "fp-1") {
		t.Fatalf("enroll = %d %q %q", code, out, errs)
	}
	if f.enroll.GetEnrollmentToken() != tok.Reveal() || !strings.Contains(f.enroll.GetPublicJwk(), `"OKP"`) || f.proofs != 1 {
		t.Fatalf("enroll request %v (proofs %d)", f.enroll, f.proofs)
	}
	kf, err := workloadclient.ReadKeyFile(keyFile)
	if err != nil || kf.Identifier == "" || kf.Server != server {
		t.Fatalf("key file after enroll: %+v, %v", kf, err)
	}
	if code, out, _ := run(t, env, "workload", "token", "--key-file", keyFile); code != 0 || strings.TrimSpace(out) != "wt-1" ||
		f.token.GetIdentifier() != kf.Identifier {
		t.Fatalf("token = %d %q, request %v", code, out, f.token)
	}
}

// TestWorkloadAttestsWithGitHubActions: --github asks the Actions runtime
// for an OIDC token with the org's audience and sends it as the attestation.
func TestWorkloadAttestsWithGitHubActions(t *testing.T) {
	f := &fakeWorkloadService{org: ids.New[ids.Org]()}
	server := workloadServer(t, f)
	var audience, bearer string
	gh := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		audience, bearer = r.URL.Query().Get("audience"), r.Header.Get("Authorization")
		_, _ = w.Write([]byte(`{"value":"gh-oidc-token"}`))
	}))
	t.Cleanup(gh.Close)
	keyFile := filepath.Join(t.TempDir(), "workload.json")
	env := envOf(map[string]string{
		"ACTIONS_ID_TOKEN_REQUEST_URL": gh.URL + "/token?api-version=2.0", "ACTIONS_ID_TOKEN_REQUEST_TOKEN": "runtime-token",
	})
	if code, _, errs := run(t, env, "workload", "init", "--key-file", keyFile); code != 0 {
		t.Fatal(errs)
	}
	code, out, errs := run(t, env, "workload", "enroll", "--key-file", keyFile, "--server", server, "--github", "--org", f.org.String())
	if code != 0 || !strings.Contains(out, "admitted") {
		t.Fatalf("enroll = %d %q %q", code, out, errs)
	}
	if audience != "pantherclaw:"+f.org.String() || bearer != "Bearer runtime-token" ||
		f.enroll.GetAttestation().GetToken() != "gh-oidc-token" ||
		f.enroll.GetAttestation().GetKind() != pantherclawv1.AttestationKind_ATTESTATION_KIND_GITHUB_ACTIONS {
		t.Fatalf("attestation: audience %q bearer %q request %v", audience, bearer, f.enroll)
	}
	if code, _, errs := run(t, envOf(nil), "workload", "enroll", "--key-file", keyFile, "--server", server, "--github", "--org", f.org.String()); code != 1 ||
		!strings.Contains(errs, "GitHub Actions") {
		t.Fatalf("outside Actions = %d %q", code, errs)
	}
	if code, _, _ := run(t, envOf(nil), "workload", "enroll", "--key-file", keyFile, "--server", server); code != 1 {
		t.Fatal("enrolled with neither a token nor an attestation")
	}
}
