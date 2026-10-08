// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Command pantherclaw-gateway: PantherClaw data plane (policy enforcement point, MCP and HTTP proxy, credential broker).
package main

import (
	"os"

	"github.com/katocxl/pantherclaw/internal/platform/cli"
)

func main() {
	os.Exit(cli.Stub("pantherclaw-gateway", "M6", os.Args[1:], os.Stdout, os.Stderr))
}
