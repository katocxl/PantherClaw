// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package rootkey

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestEncodeDecodePlainAndEncrypted(t *testing.T) {
	priv, kid, err := Generate(PurposeLicence)
	if err != nil {
		t.Fatal(err)
	}
	pub, _ := priv.Public().(ed25519.PublicKey)
	if kid != KID(PurposeLicence, pub) || !strings.HasPrefix(kid, "licence-root-") {
		t.Fatalf("kid = %s", kid)
	}
	pass := []byte("correct horse battery staple")
	for name, pp := range map[string][]byte{"plain": nil, "encrypted": pass} {
		b, err := Encode(PurposeLicence, priv, pp)
		if err != nil {
			t.Fatal(err)
		}
		if pp != nil && !bytes.Contains(b, []byte("ENCRYPTED")) {
			t.Fatalf("%s: not marked encrypted", name)
		}
		p, back, err := Decode(b, pp)
		if err != nil || p != PurposeLicence || !back.Equal(priv) {
			t.Fatalf("%s: decode = %s, %v", name, p, err)
		}
	}
}

func TestDecodeRejects(t *testing.T) {
	priv, _, _ := Generate(PurposePackages)
	pass := []byte("correct horse battery staple")
	enc, _ := Encode(PurposePackages, priv, pass)
	if _, _, err := Decode(enc, []byte("wrong passphrase!!")); !errors.Is(err, ErrKeyFile) {
		t.Fatalf("wrong passphrase: %v", err)
	}
	if _, _, err := Decode(enc, nil); !errors.Is(err, ErrKeyFile) {
		t.Fatalf("missing passphrase: %v", err)
	}
	// Relabeling the key as a licence root breaks the AAD binding.
	relabeled := bytes.Replace(enc, []byte("Purpose: packages"), []byte("Purpose: licence"), 1)
	if _, _, err := Decode(relabeled, pass); !errors.Is(err, ErrKeyFile) {
		t.Fatalf("relabeled purpose accepted: %v", err)
	}
	plain, _ := Encode(PurposePackages, priv, nil)
	other, _, _ := Generate(PurposePackages)
	otherPlain, _ := Encode(PurposePackages, other, nil)
	// Swap the kid header between files.
	kidLine := func(b []byte) string {
		for _, l := range strings.Split(string(b), "\n") {
			if strings.HasPrefix(l, "Kid: ") {
				return l
			}
		}
		return ""
	}
	swapped := strings.Replace(string(plain), kidLine(plain), kidLine(otherPlain), 1)
	if _, _, err := Decode([]byte(swapped), nil); !errors.Is(err, ErrKeyFile) {
		t.Fatalf("kid mismatch accepted: %v", err)
	}
	if _, err := Encode(PurposeLicence, priv, []byte("short")); err == nil {
		t.Fatal("short passphrase accepted")
	}
	if _, _, err := Generate("admin"); err == nil {
		t.Fatal("unknown purpose accepted")
	}
}

func TestHR063_WriteNewNeverOverwritesAndIsPrivate(t *testing.T) {
	p := filepath.Join(t.TempDir(), "licence-root.key")
	if err := WriteNew(p, []byte("x")); err != nil {
		t.Fatal(err)
	}
	if err := WriteNew(p, []byte("y")); err == nil {
		t.Fatal("existing key file overwritten")
	}
	if runtime.GOOS != "windows" {
		info, _ := os.Stat(p)
		if info.Mode().Perm() != 0o600 {
			t.Fatalf("mode = %o, want 0600", info.Mode().Perm())
		}
	}
}
