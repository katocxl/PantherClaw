// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package workloadclient

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"time"
)

// WriteTokenFile hands a workload token to a service through a file (G0
// M3 workload renewal, decision 1): the token goes to a new owner-only
// (0600) file in path's directory, which is flushed and renamed over path.
// A reader sees the old token or the new one, never part of one, and a
// symlink at path is replaced, never written through. On Windows the file
// inherits the directory's ACL, like the key file. The token is useless
// without the key (cnf.jkt), which the service holds beside it.
func WriteTokenFile(path, token string) error {
	dir, base := filepath.Split(path)
	if dir == "" {
		dir = "."
	}
	f, err := os.CreateTemp(dir, "."+base+".*.tmp") // mode 0600
	if err != nil {
		return fmt.Errorf("token file: %w", err)
	}
	tmp := f.Name()
	_, err = f.WriteString(token + "\n")
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = replace(tmp, path)
	}
	if err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("token file: %w", err)
	}
	return nil
}

// RemoveTokenFile removes the token file after a refusal, so the service
// stops presenting an identity the server refused (decision 2).
func RemoveTokenFile(path string) error {
	if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("token file: %w", err)
	}
	return nil
}

// replace renames tmp over path. On Windows the rename fails while a reader
// has path open, so it is retried for a moment.
func replace(tmp, path string) error {
	err := os.Rename(tmp, path)
	for i := 0; err != nil && runtime.GOOS == "windows" && i < 20; i++ {
		time.Sleep(25 * time.Millisecond)
		err = os.Rename(tmp, path)
	}
	return err
}
