// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package sim implements pantherclaw-sim: simulated targets and a load
// driver for tests, demos and latency measurements. Everything it does is
// SIMULATED.
package sim

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"time"

	"github.com/katocxl/pantherclaw/internal/platform/httpx"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
	"github.com/katocxl/pantherclaw/internal/platform/version"
	"github.com/katocxl/pantherclaw/internal/sim/payments"
)

const usage = `pantherclaw-sim — simulated targets and load driver (everything is SIMULATED)

Usage:
  pantherclaw-sim payments [--addr 127.0.0.1:9090] [--latency 0s] [--decline-rate 0] [--hang-rate 0]
  pantherclaw-sim load --workload-file FILE [--token-file FILE] [--run ID] [--gateway URL] [--rate 1000] [--duration 30s] [--warmup 5s] [--amount 1.00] [--out FILE]
  pantherclaw-sim version
`

// Run executes pantherclaw-sim.
func Run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		_, _ = fmt.Fprint(stderr, usage)
		return 2
	}
	var err error
	switch args[0] {
	case "version", "--version":
		_, _ = fmt.Fprintln(stdout, version.Get().String("pantherclaw-sim"))
		return 0
	case "payments":
		err = runPayments(ctx, args[1:], stderr)
	case "load":
		err = runLoad(ctx, args[1:], stdout, stderr)
	default:
		_, _ = fmt.Fprint(stderr, usage)
		return 2
	}
	if errors.Is(err, flag.ErrHelp) {
		return 2
	}
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "pantherclaw-sim: %v\n", err)
		return 1
	}
	return 0
}

func runPayments(ctx context.Context, args []string, stderr io.Writer) error {
	fs := flag.NewFlagSet("payments", flag.ContinueOnError)
	fs.SetOutput(stderr)
	addr := fs.String("addr", "127.0.0.1:9090", "listen address (loopback)")
	latency := fs.Duration("latency", 0, "added latency per request")
	decline := fs.Float64("decline-rate", 0, "probability of a 402 decline (no effect)")
	hang := fs.Float64("hang-rate", 0, "probability of never answering (unknown outcome)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	log := pclog.New(stderr, pclog.Options{Service: "pantherclaw-sim", Version: version.Get().Version})
	sim := payments.New(payments.Faults{Latency: *latency, DeclineRate: *decline, HangRate: *hang}, log)
	srv, err := httpx.NewServer(httpx.ServerConfig{Addr: *addr, Handler: sim.Handler(), Logger: log})
	if err != nil {
		return err
	}
	var lc net.ListenConfig
	ln, err := lc.Listen(ctx, "tcp", *addr)
	if err != nil {
		return err
	}
	log.InfoContext(ctx, "sim.payments_listening", slog.String("addr", ln.Addr().String()))
	errc := make(chan error, 1)
	go func() { errc <- srv.Serve(ln) }()
	select {
	case <-ctx.Done():
		sctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		return srv.Shutdown(sctx)
	case err := <-errc:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}
}
