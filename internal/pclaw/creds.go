// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pclaw

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json/v2"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// Credentials are what `pclaw login` stores (ADR-0016 decision 4): the
// server, the org, the tokens and the device key that every refresh must be
// signed with. The file is created with mode 0600 in the user's
// configuration directory; on Windows the profile directory's ACL limits
// it to the user.
type Credentials struct {
	Server       string    `json:"server"`
	Org          string    `json:"org"`
	AccessToken  string    `json:"access_token"`
	AccessExpiry time.Time `json:"access_expires_at"`
	RefreshToken string    `json:"refresh_token"`
	DeviceKey    string    `json:"device_key"` // base64url Ed25519 seed
}

// ErrNotLoggedIn is returned when no credentials are stored.
var ErrNotLoggedIn = errors.New("not logged in: run `pclaw login --server URL --org ORG`")

// credsPath returns the credentials file path (PANTHERCLAW_CONFIG_DIR
// overrides the directory, for tests and multiple profiles).
func credsPath(env Env) (string, error) {
	dir, ok := env("PANTHERCLAW_CONFIG_DIR")
	if !ok || dir == "" {
		base, err := os.UserConfigDir()
		if err != nil {
			return "", fmt.Errorf("pclaw: no user configuration directory: %w", err)
		}
		dir = filepath.Join(base, "pantherclaw")
	}
	return filepath.Join(dir, "credentials.json"), nil
}

func loadCreds(env Env) (Credentials, error) {
	p, err := credsPath(env)
	if err != nil {
		return Credentials{}, err
	}
	b, err := os.ReadFile(p) //nolint:gosec // G304: the user's own credentials file
	if errors.Is(err, os.ErrNotExist) {
		return Credentials{}, ErrNotLoggedIn
	} else if err != nil {
		return Credentials{}, err
	}
	var c Credentials
	if err := json.Unmarshal(b, &c); err != nil {
		return Credentials{}, fmt.Errorf("pclaw: credentials file %s is damaged; run pclaw login again: %w", p, err)
	}
	return c, nil
}

// saveCreds writes the file atomically with mode 0600.
func saveCreds(env Env, c Credentials) error {
	p, err := credsPath(env)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return err
	}
	b, err := json.Marshal(c)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(p), ".credentials-*")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	if err := tmp.Chmod(0o600); err != nil && !isWindows() {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(b); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), p)
}

func deleteCreds(env Env) error {
	p, err := credsPath(env)
	if err != nil {
		return err
	}
	if err := os.Remove(p); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

func (c Credentials) deviceKey() (ed25519.PrivateKey, error) {
	seed, err := base64.RawURLEncoding.DecodeString(c.DeviceKey)
	if err != nil || len(seed) != ed25519.SeedSize {
		return nil, errors.New("pclaw: credentials file has no valid device key; run pclaw login again")
	}
	return ed25519.NewKeyFromSeed(seed), nil
}
