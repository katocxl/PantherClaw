// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Command pantherclaw-gateway: PantherClaw gateway (M1.5 walking skeleton; the full gateway arrives in M6).
package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/katocxl/pantherclaw/internal/gateway"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code := gateway.Run(ctx, os.Args[1:], os.Stdout, os.Stderr, os.LookupEnv)
	stop()
	os.Exit(code)
}
