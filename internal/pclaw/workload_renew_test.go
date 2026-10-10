// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pclaw

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"connectrpc.com/connect/v2"
	"connectrpc.com/connect/v2/connecthttp"
	"google.golang.org/protobuf/types/known/timestamppb"

	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	"github.com/katocxl/pantherclaw/internal/identity/pap"
	"github.com/katocxl/pantherclaw/internal/identity/workloadclient"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// renewService answers IssueToken from a script: request n (from 1) gets
// answer(n, attestation), which returns a level or an error. Tokens live
// for life, so renewal happens every half of it.
type renewService struct {
	pantherclawv1connect.UnimplementedWorkloadServiceHandler
	life   time.Duration
	answer func(n int, attestation string) (int32, error)

	mu sync.Mutex
	// attestations holds each request's attestation token ("" for none).
	attestations []string
	// seen holds what the token file held when each request arrived.
	seen      []string
	tokenFile string
}

func (f *renewService) IssueToken(ctx context.Context, req *pantherclawv1.IssueTokenRequest) (*pantherclawv1.IssueTokenResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	info, _ := connect.CallInfoForServerContext(ctx)
	if info == nil || info.RequestHeader().Get("PAP-Proof") == "" {
		return nil, connect.NewError(connect.CodeUnauthenticated, "PAP/1: invalid_proof")
	}
	f.attestations = append(f.attestations, req.GetAttestation().GetToken())
	b, _ := os.ReadFile(f.tokenFile)
	f.seen = append(f.seen, strings.TrimSpace(string(b)))
	n := len(f.attestations)
	level, err := f.answer(n, req.GetAttestation().GetToken())
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.IssueTokenResponse{
		WorkloadToken: fmt.Sprintf("secret-wt-%d", n), ExpireTime: timestamppb.New(time.Now().Add(f.life)), AttestationLevel: level,
	}, nil
}

// renewSetup serves f and writes an enrolled key file for it.
func renewSetup(t *testing.T, f *renewService) (keyFile, tokenFile string) {
	t.Helper()
	cs := connect.NewServer()
	pantherclawv1connect.RegisterWorkloadServiceHandler(cs, f)
	mux := http.NewServeMux()
	connecthttp.Mount(mux, cs)
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)
	dir := t.TempDir()
	kf, _, err := workloadclient.NewKeyFile()
	if err != nil {
		t.Fatal(err)
	}
	kf.Identifier = "pc:org/" + ids.New[ids.Org]().String() + "/agent/" + ids.NewV7().String() + "/inst/" + ids.NewV7().String()
	kf.Server = ts.URL
	keyFile, tokenFile = filepath.Join(dir, "workload.json"), filepath.Join(dir, "token")
	if err := workloadclient.WriteKeyFile(keyFile, kf, false); err != nil {
		t.Fatal(err)
	}
	f.tokenFile = tokenFile
	return keyFile, tokenFile
}

func papRefusal(code pap.Code) error {
	return connect.NewError(connect.CodeUnauthenticated, "PAP/1: "+string(code))
}

// noSecrets fails when a token reached the command's output (HR-056).
func noSecrets(t *testing.T, outs ...string) {
	t.Helper()
	for _, s := range outs {
		if strings.Contains(s, "secret-") {
			t.Fatalf("a token reached the output: %q", s)
		}
	}
}

// TestWorkloadRenewKeepsTheTokenFileFresh: the renewer replaces the token
// file with each new token before the last one expires, retries a failure
// while the current token stays, and on a refusal (here the instance was
// revoked) removes the file and exits 3 with what to do next. No token
// ever reaches its output.
func TestWorkloadRenewKeepsTheTokenFileFresh(t *testing.T) {
	f := &renewService{life: 600 * time.Millisecond, answer: func(n int, _ string) (int32, error) {
		switch n {
		case 3:
			return 0, connect.NewError(connect.CodeUnavailable, "server restarting")
		case 6:
			return 0, papRefusal(pap.CodeInstanceNotAdmitted)
		}
		return 1, nil
	}}
	keyFile, tokenFile := renewSetup(t, f)
	code, out, errs := run(t, envOf(nil), "workload", "renew", "--key-file", keyFile, "--out", tokenFile)
	if code != exitRefused || !strings.Contains(errs, "instance_not_admitted") || !strings.Contains(errs, "pclaw instance get") ||
		!strings.Contains(errs, "The token file was removed") {
		t.Fatalf("renew = %d %q %q", code, out, errs)
	}
	if !strings.Contains(errs, "renewal failed: unavailable: server restarting; retrying in") || strings.Count(errs, "(L1, valid until") != 4 {
		t.Fatalf("stderr %q", errs)
	}
	noSecrets(t, out, errs)
	if _, err := os.Stat(tokenFile); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("the token file outlived the refusal: %v", err)
	}
	// Each request found the token before it in the file; the failed
	// request changed nothing.
	want := []string{"", "secret-wt-1", "secret-wt-2", "secret-wt-2", "secret-wt-4", "secret-wt-5"}
	if !slices.Equal(f.seen, want) {
		t.Fatalf("the file held %q, want %q", f.seen, want)
	}
}

// TestWorkloadRenewReattestsKubernetesOnlyAfterRotation: a projected
// token is sent once (HR-143). The one the workload enrolled with is
// already used, so the server refuses it (invalid_token) and the renewer
// asks again without it; after the kubelet rotates the file the new token
// is sent once; a level change is reported, and a key that is no longer
// the instance's ends renewal.
func TestWorkloadRenewReattestsKubernetesOnlyAfterRotation(t *testing.T) {
	projected := filepath.Join(t.TempDir(), "k8s-token")
	if err := os.WriteFile(projected, []byte("k8s-1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	f := &renewService{life: 600 * time.Millisecond}
	f.answer = func(n int, att string) (int32, error) {
		switch n {
		case 1:
			return 0, papRefusal(pap.CodeInvalidToken) // k8s-1 was used by enroll
		case 3:
			if err := os.WriteFile(projected, []byte("k8s-2\n"), 0o600); err != nil {
				return 0, err
			}
		case 5:
			return 1, nil // the attestation lapsed
		case 6:
			return 0, papRefusal(pap.CodeKeyMismatch)
		}
		return 2, nil
	}
	keyFile, tokenFile := renewSetup(t, f)
	code, out, errs := run(t, envOf(nil), "workload", "renew", "--key-file", keyFile, "--out", tokenFile, "--kubernetes-token", projected)
	if code != exitRefused || !strings.Contains(errs, "key_mismatch") || !strings.Contains(errs, "new instance") {
		t.Fatalf("renew = %d %q %q", code, out, errs)
	}
	if want := []string{"k8s-1", "", "", "k8s-2", "", ""}; !slices.Equal(f.attestations, want) {
		t.Fatalf("attestations %q, want %q", f.attestations, want)
	}
	if !strings.Contains(errs, "refused the attestation (invalid_token") || !strings.Contains(errs, "changed from L2 to L1") {
		t.Fatalf("stderr %q", errs)
	}
	noSecrets(t, out, errs)
}

// TestWorkloadRenewReattestsWithGitHubEveryTime: each renewal asks the
// Actions runtime for a fresh token; a refused attestation is retried
// without one, and an instance that is no longer admitted ends renewal
// even when an attestation was sent.
func TestWorkloadRenewReattestsWithGitHubEveryTime(t *testing.T) {
	var mu sync.Mutex
	minted := 0
	gh := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		minted++
		_, _ = fmt.Fprintf(w, `{"value":"gh-%d"}`, minted)
	}))
	t.Cleanup(gh.Close)
	f := &renewService{life: 600 * time.Millisecond, answer: func(n int, _ string) (int32, error) {
		switch n {
		case 3:
			return 0, papRefusal(pap.CodeAttestationLow)
		case 5:
			return 0, papRefusal(pap.CodeInstanceNotAdmitted)
		}
		return 2, nil
	}}
	keyFile, tokenFile := renewSetup(t, f)
	env := envOf(map[string]string{"ACTIONS_ID_TOKEN_REQUEST_URL": gh.URL + "/token", "ACTIONS_ID_TOKEN_REQUEST_TOKEN": "runtime"})
	code, out, errs := run(t, env, "workload", "renew", "--key-file", keyFile, "--out", tokenFile, "--github")
	if code != exitRefused || !strings.Contains(errs, "instance_not_admitted") {
		t.Fatalf("renew = %d %q %q", code, out, errs)
	}
	if want := []string{"gh-1", "gh-2", "gh-3", "", "gh-4"}; !slices.Equal(f.attestations, want) {
		t.Fatalf("attestations %q, want %q", f.attestations, want)
	}
	noSecrets(t, out, errs)
}

// TestWorkloadRenewStopsCleanly: a stop between renewals exits 0 and
// leaves the current token in place for the service (decision 2).
func TestWorkloadRenewStopsCleanly(t *testing.T) {
	f := &renewService{life: time.Minute, answer: func(int, string) (int32, error) { return 1, nil }}
	keyFile, tokenFile := renewSetup(t, f)
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan int, 1)
	var out, errb bytes.Buffer
	go func() {
		done <- Run(ctx, []string{"workload", "renew", "--key-file", keyFile, "--out", tokenFile}, &out, &errb, envOf(nil), Options{})
	}()
	deadline := time.Now().Add(10 * time.Second)
	for {
		if b, err := os.ReadFile(tokenFile); err == nil && strings.TrimSpace(string(b)) == "secret-wt-1" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("no token file; stderr %q", errb.String())
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	if code := <-done; code != 0 {
		t.Fatalf("renew after a stop = %d %q", code, errb.String())
	}
	if b, err := os.ReadFile(tokenFile); err != nil || strings.TrimSpace(string(b)) != "secret-wt-1" {
		t.Fatalf("token file after a stop: %q, %v", b, err)
	}
	noSecrets(t, out.String(), errb.String())

	if code, _, _ := run(t, envOf(nil), "workload", "renew", "--key-file", keyFile); code != 2 {
		t.Fatal("renew without --out was accepted")
	}
	if code, _, errs := run(t, envOf(nil), "workload", "renew", "--key-file", keyFile, "--out", tokenFile, "--github", "--kubernetes-token", "x"); code != 1 ||
		!strings.Contains(errs, "not both") {
		t.Fatalf("both attestations = %d %q", code, errs)
	}
	fresh := filepath.Join(t.TempDir(), "fresh.json")
	if code, _, _ := run(t, envOf(nil), "workload", "init", "--key-file", fresh); code != 0 {
		t.Fatal("init")
	}
	if code, _, errs := run(t, envOf(nil), "workload", "renew", "--key-file", fresh, "--out", tokenFile); code != 1 || !strings.Contains(errs, "not enrolled") {
		t.Fatalf("unenrolled key = %d %q", code, errs)
	}
}
