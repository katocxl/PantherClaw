// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package gateway

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/credentials/domain"
	"github.com/katocxl/pantherclaw/internal/gateway/broker"
	pccrypto "github.com/katocxl/pantherclaw/internal/platform/crypto"
	"github.com/katocxl/pantherclaw/internal/platform/keys"
)

// TestHR182_TheGatewayRegistersItsBrokerKeyAndOpensWithTheRegisteredID:
// `broker-key generate` writes a key and prints its fingerprint; the
// broker registers the key until the server answers, is ready only then,
// and opens credentials sealed to the id the server gave it.
func TestHR182_TheGatewayRegistersItsBrokerKeyAndOpensWithTheRegisteredID(t *testing.T) {
	dir := t.TempDir()
	kek := filepath.Join(dir, "kek")
	if err := keys.GenerateKEKFile(kek); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "broker.json")
	var out, errs bytes.Buffer
	if code := Run(context.Background(), []string{"broker-key", "generate", "--out", path, "--kek-file", kek}, &out, &errs, nil); code != 0 {
		t.Fatalf("generate = %d %q", code, errs.String())
	}
	key, err := broker.Load(t.Context(), path, []string{kek})
	if err != nil || !strings.Contains(out.String(), key.Fingerprint()) {
		t.Fatalf("load: %v; output %q", err, out.String())
	}
	if code := Run(context.Background(), []string{"broker-key", "generate", "--out", path}, &out, &errs, nil); code == 0 {
		t.Fatal("generate without a KEK file succeeded")
	}

	var calls atomic.Int32
	b := NewBroker(key, func(_ context.Context, public []byte) (string, error) {
		if !bytes.Equal(public, key.PublicKey()) {
			t.Error("registered another key")
		}
		if calls.Add(1) < 2 {
			return "", errors.New("server unavailable")
		}
		return "bk-1", nil
	}, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	go func() { _ = b.Run(ctx) }()
	select {
	case <-b.Ready():
		t.Fatal("ready before registering")
	case <-time.After(100 * time.Millisecond):
	}
	select {
	case <-b.Ready():
	case <-ctx.Done():
		t.Fatal("not registered after a retry")
	}
	pub, _ := pccrypto.ParseSealPublicKey(key.PublicKey())
	bind := domain.Binding{Org: "o", Connection: "c", Version: 1, AllowedHosts: []string{"h"}, BrokerKey: "bk-1", Header: "Authorization"}
	blob, _ := pccrypto.Seal(pub, bind.Info(), domain.AAD, []byte("secret"))
	pt, err := b.Open("o", "c", []string{"h"}, broker.Sealed{Version: 1, BrokerKey: "bk-1", Blob: blob, Header: "Authorization"})
	if err != nil || string(pt) != "secret" {
		t.Fatalf("open: %q %v", pt, err)
	}
	var none *Broker
	if _, err := none.Open("o", "c", nil, broker.Sealed{}); !errors.Is(err, broker.ErrNoBroker) {
		t.Fatalf("no broker: %v", err)
	}
}

func TestBrokerConfigIsPaired(t *testing.T) {
	c := DefaultConfig()
	c.Target.URL = "http://127.0.0.1:9090"
	c.Broker.KeyFile = "broker.json"
	if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "broker") {
		t.Fatalf("a key file without KEK files: %v", err)
	}
	c.Broker.KEKFiles = []string{"kek"}
	c.Egress.AllowedPrefixes = []string{"10.0.0.0/8"}
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	c.Egress.AllowedPrefixes = []string{"10.0.0.0"}
	if err := c.Validate(); err == nil {
		t.Fatal("a prefix without a length was accepted")
	}
}
