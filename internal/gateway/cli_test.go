// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package gateway

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/katocxl/pantherclaw/internal/gateway/control"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
)

func noEnv(string) (string, bool) { return "", false }

func TestEnrollFileIsReadStrictly(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	good := write("good.json", `{"api_url":"http://127.0.0.1:8080","token":"pcg_x","ca_sha256":"`+testPin+`"}`)
	if f, err := ReadEnrollFile(good); err != nil || f.Token != "pcg_x" {
		t.Fatalf("good file: %+v %v", f, err)
	}
	for name, body := range map[string]string{
		"unknown field": `{"api_url":"http://127.0.0.1:8080","token":"pcg_x","ca_sha256":"` + testPin + `","x":1}`,
		"no token":      `{"api_url":"http://127.0.0.1:8080","ca_sha256":"` + testPin + `"}`,
		"bad pin":       `{"api_url":"http://127.0.0.1:8080","token":"pcg_x","ca_sha256":"sha256:00"}`,
		"not json":      `api_url=x`,
	} {
		if _, err := ReadEnrollFile(write(name+".json", body)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// TestHR180_AGatewayWithoutIdentityOrEnrollmentRefusesToStart: no saved
// identity and no enrollment file means no certificate, so nothing serves.
func TestHR180_AGatewayWithoutIdentityOrEnrollmentRefusesToStart(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Control.IdentityDir = t.TempDir()
	if _, err := LoadOrEnroll(context.Background(), &cfg, "", pclog.Discard()); !errors.Is(err, control.ErrNoIdentity) {
		t.Fatalf("no identity: %v", err)
	}
	// An enrollment file whose pin differs from the configured one is refused
	// before anything is sent.
	cfg.Control.CASHA256 = "sha256:" + strings.Repeat("1", 64)
	f := filepath.Join(t.TempDir(), "enroll.json")
	if err := os.WriteFile(f, []byte(`{"api_url":"http://127.0.0.1:1","token":"pcg_x","ca_sha256":"`+testPin+`"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadOrEnroll(context.Background(), &cfg, f, pclog.Discard()); !errors.Is(err, control.ErrPin) {
		t.Fatalf("pin mismatch: %v", err)
	}
}

func TestRunUsage(t *testing.T) {
	var out, errb bytes.Buffer
	if code := Run(context.Background(), nil, &out, &errb, noEnv); code != 2 {
		t.Fatalf("no args: %d", code)
	}
	if code := Run(context.Background(), []string{"version"}, &out, &errb, noEnv); code != 0 || !strings.HasPrefix(out.String(), "pantherclaw-gateway") {
		t.Fatalf("version: %d %q", code, out.String())
	}
	if code := Run(context.Background(), []string{"enroll"}, &out, &errb, noEnv); code != 1 {
		t.Fatalf("enroll without a token file: %d", code)
	}
}
