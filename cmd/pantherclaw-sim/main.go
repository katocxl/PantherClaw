// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Command pantherclaw-sim: PantherClaw target simulators and load driver for tests and demos (SIMULATED).
package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/katocxl/pantherclaw/internal/sim"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code := sim.Run(ctx, os.Args[1:], os.Stdout, os.Stderr)
	stop()
	os.Exit(code)
}
