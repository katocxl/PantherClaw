// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package workloadclient_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/katocxl/pantherclaw/internal/identity/workloadclient"
)

// TestKeyFileRoundTripAndNoOverwrite: the key survives the file, the file
// is private, and an existing file is kept unless replace is asked.
func TestKeyFileRoundTripAndNoOverwrite(t *testing.T) {
	path := filepath.Join(t.TempDir(), "workload.json")
	kf, key, err := workloadclient.NewKeyFile()
	if err != nil {
		t.Fatal(err)
	}
	kf.Identifier = "pc:org/x/agent/y/inst/z"
	if err := workloadclient.WriteKeyFile(path, kf, false); err != nil {
		t.Fatal(err)
	}
	got, err := workloadclient.ReadKeyFile(path)
	if err != nil || got.Identifier != kf.Identifier {
		t.Fatalf("read: %+v, %v", got, err)
	}
	if k, err := got.Key(); err != nil || !k.Equal(key) {
		t.Fatalf("key: %v", err)
	}
	if err := workloadclient.WriteKeyFile(path, kf, false); err == nil {
		t.Error("overwrote an existing key file")
	}
	if err := os.WriteFile(path, []byte(`{"private_key":"short"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := workloadclient.ReadKeyFile(path); err == nil {
		t.Error("accepted a malformed key")
	}
}
