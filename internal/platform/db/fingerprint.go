// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package db

import (
	"crypto/sha256"
	"encoding/hex"
	"io/fs"
	"sort"

	"github.com/katocxl/pantherclaw/migrations"
)

// SchemaFingerprint hashes the bootstrap SQL and every migration file. Test
// harnesses use it to name migrated template databases.
func SchemaFingerprint() string {
	h := sha256.New()
	h.Write([]byte(bootstrapRolesSQL))
	h.Write([]byte{0})
	h.Write([]byte(bootstrapDatabaseSQL))
	var names []string
	_ = fs.WalkDir(migrations.FS, ".", func(p string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			names = append(names, p)
		}
		return nil
	})
	sort.Strings(names)
	for _, n := range names {
		b, _ := fs.ReadFile(migrations.FS, n)
		h.Write([]byte{0})
		h.Write([]byte(n))
		h.Write([]byte{0})
		h.Write(b)
	}
	goFP, err := migrations.Fingerprint()
	if err != nil {
		goFP = "unavailable:" + err.Error()
	}
	h.Write([]byte{0})
	h.Write([]byte(goFP))
	return hex.EncodeToString(h.Sum(nil))[:16]
}
