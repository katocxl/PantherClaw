// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Command pantherclaw-sim: PantherClaw target simulators (payments, CRM, git) for tests and demos.
package main

import (
	"os"

	"github.com/katocxl/pantherclaw/internal/platform/cli"
)

func main() {
	os.Exit(cli.Stub("pantherclaw-sim", "M1.5", os.Args[1:], os.Stdout, os.Stderr))
}
