// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package broker

import (
	"bytes"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/katocxl/pantherclaw/internal/credentials/domain"
	pccrypto "github.com/katocxl/pantherclaw/internal/platform/crypto"
	"github.com/katocxl/pantherclaw/internal/platform/keys"
)

func kekFile(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "kek")
	if err := keys.GenerateKEKFile(p); err != nil {
		t.Fatal(err)
	}
	return p
}

// TestHR182_TheBrokerKeyIsStoredWrappedAndChecked: the private key never
// reaches disk in the clear, loads only with its key-encryption key, and a
// file whose parts do not match is refused.
func TestHR182_TheBrokerKeyIsStoredWrappedAndChecked(t *testing.T) {
	kek := kekFile(t)
	path := filepath.Join(t.TempDir(), "broker", "key.json")
	fp, err := Generate(t.Context(), path, []string{kek})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Generate(t.Context(), path, []string{kek}); err == nil {
		t.Fatal("an existing key file was overwritten")
	}
	k, err := Load(t.Context(), path, []string{kek})
	if err != nil || k.Fingerprint() != fp || Fingerprint(k.PublicKey()) != fp {
		t.Fatalf("load: %v", err)
	}
	raw, err := k.priv.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	file, _ := os.ReadFile(path)
	if bytes.Contains(file, raw) {
		t.Fatal("the private key is in the file in the clear")
	}
	if _, err := Load(t.Context(), path, []string{kekFile(t)}); !errors.Is(err, ErrKeyFile) {
		t.Fatalf("another KEK: %v", err)
	}
	other := filepath.Join(t.TempDir(), "other.json")
	if _, err := Generate(t.Context(), other, []string{kek}); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(other)
	swapped := bytes.Replace(file, []byte(fp), []byte(Fingerprint([]byte("x"))), 1)
	for name, content := range map[string][]byte{"swapped fingerprint": swapped, "not json": []byte("{"), "empty": nil} {
		bad := filepath.Join(t.TempDir(), "bad.json")
		if err := os.WriteFile(bad, content, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := Load(t.Context(), bad, []string{kek}); !errors.Is(err, ErrKeyFile) {
			t.Errorf("%s: %v", name, err)
		}
	}
	_ = b
}

// TestHR060_ACredentialOpensOnlyWithTheGatewaysOwnBinding: the gateway
// rebuilds the binding from its own view; another org, connection, version
// or host list, or a blob sealed to another key id, does not open.
func TestHR060_ACredentialOpensOnlyWithTheGatewaysOwnBinding(t *testing.T) {
	kek := kekFile(t)
	path := filepath.Join(t.TempDir(), "key.json")
	if _, err := Generate(t.Context(), path, []string{kek}); err != nil {
		t.Fatal(err)
	}
	k, err := Load(t.Context(), path, []string{kek})
	if err != nil {
		t.Fatal(err)
	}
	pub, _ := pccrypto.ParseSealPublicKey(k.PublicKey())
	b := domain.Binding{
		Org: "org-1", Connection: "conn-1", Version: 2, AllowedHosts: []string{"payments.example.test"}, BrokerKey: "key-1",
		Header: "Authorization", Scheme: "Bearer",
	}
	blob, err := pccrypto.Seal(pub, b.Info(), domain.AAD, []byte("sk_test_value"))
	if err != nil {
		t.Fatal(err)
	}
	s := Sealed{Version: 2, BrokerKey: "key-1", Blob: blob, Header: "Authorization", Scheme: "Bearer"}
	pt, err := k.Open("org-1", "conn-1", []string{"payments.example.test"}, "key-1", s)
	if err != nil || string(pt) != "sk_test_value" {
		t.Fatalf("open: %q %v", pt, err)
	}
	for name, try := range map[string]func() ([]byte, error){
		"another org": func() ([]byte, error) {
			return k.Open("org-2", "conn-1", []string{"payments.example.test"}, "key-1", s)
		},
		"another connection": func() ([]byte, error) {
			return k.Open("org-1", "conn-2", []string{"payments.example.test"}, "key-1", s)
		},
		"other hosts": func() ([]byte, error) { return k.Open("org-1", "conn-1", []string{"evil.example.test"}, "key-1", s) },
		"another version": func() ([]byte, error) {
			v := s
			v.Version = 3
			return k.Open("org-1", "conn-1", []string{"payments.example.test"}, "key-1", v)
		},
		"another placement": func() ([]byte, error) {
			v := s
			v.Header = "X-Leak"
			return k.Open("org-1", "conn-1", []string{"payments.example.test"}, "key-1", v)
		},
		"sealed to another key": func() ([]byte, error) {
			return k.Open("org-1", "conn-1", []string{"payments.example.test"}, "key-2", s)
		},
	} {
		if _, err := try(); !errors.Is(err, ErrOpen) {
			t.Errorf("%s: %v", name, err)
		}
	}
	var none *Key
	if _, err := none.Open("org-1", "conn-1", nil, "key-1", s); !errors.Is(err, ErrNoBroker) {
		t.Errorf("no broker key: %v", err)
	}
}

// TestHR060_TheCredentialGoesOnlyToItsHosts: placement refuses any other
// host or port.
func TestHR060_TheCredentialGoesOnlyToItsHosts(t *testing.T) {
	hosts := []string{"payments.example.test", "auth.example.test:8443"}
	for url, ok := range map[string]bool{
		"https://payments.example.test/v1/refunds":        true,
		"https://PAYMENTS.example.test:9443/x":            true,
		"https://auth.example.test:8443/token":            true,
		"https://auth.example.test/token":                 false,
		"https://evil.example.test/x":                     false,
		"https://payments.example.test.evil.example/x":    false,
		"http://auth.example.test:8443/token":             true,
		"https://payments.example.test@evil.example.test": false,
	} {
		r := httptest.NewRequest(http.MethodGet, url, nil)
		err := Place(r, hosts, "Authorization", "Bearer", []byte("secret"))
		if ok != (err == nil) {
			t.Errorf("%s: %v", url, err)
		}
		if ok && r.Header.Get("Authorization") != "Bearer secret" {
			t.Errorf("%s: header %q", url, r.Header.Get("Authorization"))
		}
		if !ok && r.Header.Get("Authorization") != "" {
			t.Errorf("%s: the credential was placed on a refused request", url)
		}
	}
}
