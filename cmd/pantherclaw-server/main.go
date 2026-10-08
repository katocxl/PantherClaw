// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Command pantherclaw-server: PantherClaw control plane (API, Transaction Authority, workers).
package main

import (
	"os"

	"github.com/katocxl/pantherclaw/internal/platform/cli"
)

func main() {
	os.Exit(cli.Stub("pantherclaw-server", "M1", os.Args[1:], os.Stdout, os.Stderr))
}
