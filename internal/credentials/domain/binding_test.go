// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain_test

import (
	"bytes"
	"errors"
	"testing"

	"github.com/katocxl/pantherclaw/internal/credentials/domain"
	pccrypto "github.com/katocxl/pantherclaw/internal/platform/crypto"
)

func binding() domain.Binding {
	return domain.Binding{
		Org: "0192aaaa-bbbb-7ccc-8ddd-000000000001", Connection: "0192aaaa-bbbb-7ccc-8ddd-000000000002", Version: 3,
		AllowedHosts: []string{"payments.example.test", "auth.example.test:8443"}, BrokerKey: "0192aaaa-bbbb-7ccc-8ddd-000000000003",
		Header: "Authorization", Scheme: "Bearer",
	}
}

// TestHR060_ASealedCredentialOpensOnlyForItsBinding: a blob opens with the
// broker key and the exact binding it was sealed for; any other org,
// connection, version, host list, broker key or placement fails, and the
// order of the hosts does not matter.
func TestHR060_ASealedCredentialOpensOnlyForItsBinding(t *testing.T) {
	key, err := pccrypto.GenerateSealKey()
	if err != nil {
		t.Fatal(err)
	}
	b := binding()
	secret := []byte("sk_live_very_secret")
	sealed, err := pccrypto.Seal(key.PublicKey(), b.Info(), domain.AAD, secret)
	if err != nil {
		t.Fatal(err)
	}
	if err := domain.CheckFormat(sealed); err != nil {
		t.Fatalf("format: %v", err)
	}
	if bytes.Contains(sealed, secret) {
		t.Fatal("the plaintext is visible in the blob")
	}
	reordered := b
	reordered.AllowedHosts = []string{b.AllowedHosts[1], b.AllowedHosts[0]}
	if got, err := pccrypto.Open(key, reordered.Info(), domain.AAD, sealed); err != nil || !bytes.Equal(got, secret) {
		t.Fatalf("open: %q %v", got, err)
	}
	for name, change := range map[string]func(*domain.Binding){
		"org":        func(b *domain.Binding) { b.Org = "0192aaaa-bbbb-7ccc-8ddd-000000000009" },
		"connection": func(b *domain.Binding) { b.Connection = "0192aaaa-bbbb-7ccc-8ddd-000000000009" },
		"version":    func(b *domain.Binding) { b.Version = 4 },
		"hosts":      func(b *domain.Binding) { b.AllowedHosts = []string{"payments.example.test"} },
		"broker key": func(b *domain.Binding) { b.BrokerKey = "0192aaaa-bbbb-7ccc-8ddd-000000000009" },
		"header":     func(b *domain.Binding) { b.Header = "X-Api-Key" },
		"scheme":     func(b *domain.Binding) { b.Scheme = "" },
	} {
		other := binding()
		change(&other)
		if _, err := pccrypto.Open(key, other.Info(), domain.AAD, sealed); !errors.Is(err, pccrypto.ErrDecrypt) {
			t.Errorf("%s: %v", name, err)
		}
	}
	another, err := pccrypto.GenerateSealKey()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pccrypto.Open(another, b.Info(), domain.AAD, sealed); !errors.Is(err, pccrypto.ErrDecrypt) {
		t.Errorf("another broker key: %v", err)
	}
}

func TestSealedFormatIsChecked(t *testing.T) {
	key, _ := pccrypto.GenerateSealKey()
	sealed, _ := pccrypto.Seal(key.PublicKey(), binding().Info(), domain.AAD, []byte("x"))
	if len(sealed) != domain.MinSealed || domain.CheckFormat(sealed) != nil {
		t.Fatalf("a one-byte credential is %d bytes", len(sealed))
	}
	for name, blob := range map[string][]byte{
		"empty":          nil,
		"short":          sealed[:len(sealed)-1],
		"wrong version":  append([]byte{0x02}, sealed[1:]...),
		"wrong enc size": append([]byte{0x01, 0x04, 0x61}, sealed[3:]...),
		"too long":       make([]byte, domain.MaxSealed+1),
	} {
		if err := domain.CheckFormat(blob); !errors.Is(err, domain.ErrFormat) {
			t.Errorf("%s: %v", name, err)
		}
	}
}
