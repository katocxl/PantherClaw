// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Command pclaw-admin: offline root key generation, licence signing and
// tool package signing.
// Run it only on an offline-capable machine (HR-063).
package main

import (
	"os"
	"time"

	"github.com/katocxl/pantherclaw/internal/admincli"
)

func main() {
	os.Exit(admincli.Run(os.Args[1:], os.Stdout, os.Stderr, time.Now))
}
