// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Command pclaw-admin: PantherClaw offline administration (licence and package signing roots).
package main

import (
	"os"

	"github.com/katocxl/pantherclaw/internal/platform/cli"
)

func main() {
	os.Exit(cli.Stub("pclaw-admin", "M1", os.Args[1:], os.Stdout, os.Stderr))
}
