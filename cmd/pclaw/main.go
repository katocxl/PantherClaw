// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Command pclaw: PantherClaw command-line interface.
package main

import (
	"os"

	"github.com/katocxl/pantherclaw/internal/platform/cli"
)

func main() {
	os.Exit(cli.Stub("pclaw", "M2", os.Args[1:], os.Stdout, os.Stderr))
}
