// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"

	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
)

// MaxSecretBytes caps secret files (passwords, KEKs, licence files).
const MaxSecretBytes = 64 << 10

// ErrSecretFile wraps every secret-file error. Messages name the path but
// never include file contents.
var ErrSecretFile = errors.New("config: secret file")

// ReadSecretFile reads a secret from a file mount (SB-7). One trailing
// newline (LF or CRLF) is removed. On Unix-like systems the file must not be
// readable or writable by group or others; NTFS permissions are not checked
// (BUILD_GUIDE §4).
func ReadSecretFile(path string) (pclog.Secret[[]byte], error) {
	var none pclog.Secret[[]byte]
	if path == "" {
		return none, fmt.Errorf("%w: no path configured", ErrSecretFile)
	}
	f, err := os.Open(path) //nolint:gosec // G304: the operator chooses secret mount paths
	if err != nil {
		return none, fmt.Errorf("%w: open %s: %w", ErrSecretFile, path, err)
	}
	defer func() { _ = f.Close() }()
	info, err := f.Stat()
	if err != nil {
		return none, fmt.Errorf("%w: stat %s: %w", ErrSecretFile, path, err)
	}
	if !info.Mode().IsRegular() {
		return none, fmt.Errorf("%w: %s is not a regular file", ErrSecretFile, path)
	}
	if err := checkPerm(info.Mode()); err != nil {
		return none, fmt.Errorf("%w: %s: %w", ErrSecretFile, path, err)
	}
	b, err := io.ReadAll(io.LimitReader(f, MaxSecretBytes+1))
	if err != nil {
		return none, fmt.Errorf("%w: read %s: %w", ErrSecretFile, path, err)
	}
	if len(b) > MaxSecretBytes {
		return none, fmt.Errorf("%w: %s exceeds %d bytes", ErrSecretFile, path, MaxSecretBytes)
	}
	b = bytes.TrimSuffix(b, []byte("\n"))
	b = bytes.TrimSuffix(b, []byte("\r"))
	if len(b) == 0 {
		return none, fmt.Errorf("%w: %s is empty", ErrSecretFile, path)
	}
	return pclog.NewSecret(b), nil
}

func checkPerm(mode os.FileMode) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	if mode.Perm()&0o077 != 0 {
		return fmt.Errorf("permissions %04o allow group/other access; use 0600 or 0400", mode.Perm())
	}
	return nil
}
