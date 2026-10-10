// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"context"
	"crypto/ed25519"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"maps"
	"os"
	"path/filepath"

	"github.com/katocxl/pantherclaw/internal/definitions/trust"
	"github.com/katocxl/pantherclaw/internal/platform/crypto/jws"
	"github.com/katocxl/pantherclaw/internal/platform/rootkey"
)

// packageRoots returns the roots the API verifies package imports with:
// the embedded package roots and, when dev.package_key_file names it, the
// development package key (HR-163). Validate refuses that setting unless
// the server is reachable only from this machine; the check is repeated
// here so that no other path can skip it. A missing key file is not an
// error: `dev seed` creates it, and until then no development key is
// trusted.
func packageRoots(ctx context.Context, cfg *Config, log *slog.Logger) (trust.Roots, error) {
	roots, err := trust.EmbeddedRoots()
	if err != nil || cfg.Dev.PackageKeyFile == "" {
		return roots, err
	}
	if err := cfg.localOnly(); err != nil {
		return nil, fmt.Errorf("server: dev.package_key_file is development-only (HR-163): %w", err)
	}
	b, err := os.ReadFile(cfg.Dev.PackageKeyFile)
	if errors.Is(err, fs.ErrNotExist) {
		log.WarnContext(ctx, "packages.dev_key_missing", slog.String("file", cfg.Dev.PackageKeyFile),
			slog.String("note", "dev seed creates it; until then no development package key is trusted"))
		return roots, nil
	}
	if err != nil {
		return nil, fmt.Errorf("server: dev.package_key_file: %w", err)
	}
	dev, err := trust.ParseDevKey(b)
	if err != nil {
		return nil, fmt.Errorf("server: dev.package_key_file: %w", err)
	}
	all := maps.Clone(roots)
	for kid, pub := range dev {
		all[kid] = pub
		log.WarnContext(ctx, "packages.dev_key_trusted", slog.String("kid", kid),
			slog.String("note", "DEVELOPMENT ONLY: package imports signed with this key are trusted"))
	}
	return all, nil
}

// devPackageSigner returns the key `dev seed` signs the reference packages
// with. With dev.package_key_file it is the development package key,
// created on the first run (0600, never overwritten) and reused afterwards
// (HR-163). Without it, it is a throwaway key that nothing keeps and no
// server trusts (G0 M4 part 2).
func devPackageSigner(cfg *Config, stdout io.Writer) (*jws.Signer, error) {
	pubPath := cfg.Dev.PackageKeyFile
	if pubPath == "" {
		priv, kid, err := rootkey.Generate(rootkey.PurposePackages)
		if err != nil {
			return nil, err
		}
		return jws.NewSigner(kid, priv)
	}
	privPath := devPrivateKeyFile(pubPath)
	b, err := os.ReadFile(privPath) //nolint:gosec // G304: the configured development key
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return createDevPackageKey(privPath, pubPath, stdout)
	case err != nil:
		return nil, fmt.Errorf("dev seed: development package key: %w", err)
	}
	p, priv, err := rootkey.Decode(b, nil)
	if err != nil {
		return nil, fmt.Errorf("dev seed: %s: %w", privPath, err)
	}
	if p != rootkey.PurposeDevPackages {
		return nil, fmt.Errorf("dev seed: %s is a %s key, not a development package key", privPath, p)
	}
	pub, _ := priv.Public().(ed25519.PublicKey)
	signer, err := jws.NewSigner(trust.DevKID(pub), priv)
	if err != nil {
		return nil, err
	}
	pb, err := os.ReadFile(pubPath) //nolint:gosec // G304: the configured development key
	if errors.Is(err, fs.ErrNotExist) {
		return signer, writeDevPublicKey(pubPath, signer)
	}
	if err != nil {
		return nil, fmt.Errorf("dev seed: development package key: %w", err)
	}
	roots, err := trust.ParseDevKey(pb)
	if err != nil {
		return nil, fmt.Errorf("dev seed: %s: %w", pubPath, err)
	}
	if !roots[signer.KeyID()].Equal(signer.Public()) {
		return nil, fmt.Errorf("dev seed: %s does not hold the public half of %s; remove both to create a new pair", pubPath, privPath)
	}
	return signer, nil
}

func createDevPackageKey(privPath, pubPath string, stdout io.Writer) (*jws.Signer, error) {
	if _, err := os.Stat(pubPath); err == nil {
		return nil, fmt.Errorf("dev seed: %s exists without its private key %s; remove it to create a new pair", pubPath, privPath)
	}
	priv, kid, err := rootkey.Generate(rootkey.PurposeDevPackages)
	if err != nil {
		return nil, err
	}
	pem, err := rootkey.Encode(rootkey.PurposeDevPackages, priv, nil)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(privPath), 0o700); err != nil {
		return nil, fmt.Errorf("dev seed: %w", err)
	}
	if err := rootkey.WriteNew(privPath, pem); err != nil {
		return nil, fmt.Errorf("dev seed: %w", err)
	}
	signer, err := jws.NewSigner(kid, priv)
	if err != nil {
		return nil, err
	}
	if err := writeDevPublicKey(pubPath, signer); err != nil {
		return nil, err
	}
	_, _ = fmt.Fprintf(stdout, "created development package key %s in %s; local servers with dev.package_key_file trust it (HR-163)\n", kid, privPath)
	return signer, nil
}

func writeDevPublicKey(path string, signer *jws.Signer) error {
	b, err := json.Marshal(struct {
		Keys []jws.JWK `json:"keys"`
	}{Keys: []jws.JWK{jws.PublicJWK(signer.Public(), signer.KeyID())}})
	if err != nil {
		return err
	}
	if err := rootkey.WriteNew(path, append(b, '\n')); err != nil {
		return fmt.Errorf("dev seed: %w", err)
	}
	return nil
}
