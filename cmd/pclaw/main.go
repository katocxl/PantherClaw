// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Command pclaw: PantherClaw command-line interface.
package main

import (
	"context"
	"errors"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"runtime"

	"github.com/katocxl/pantherclaw/internal/pclaw"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	code := pclaw.Run(ctx, os.Args[1:], os.Stdout, os.Stderr, os.LookupEnv, pclaw.Options{OpenBrowser: openBrowser})
	stop()
	os.Exit(code)
}

// openBrowser opens an http(s) URL with the platform's handler. The URL was
// checked to be on the configured server; it is passed as one argument,
// never through a shell.
func openBrowser(ctx context.Context, raw string) error {
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") {
		return errors.New("refusing to open a non-http URL")
	}
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.CommandContext(ctx, "rundll32", "url.dll,FileProtocolHandler", u.String()) //nolint:gosec // G204: fixed program, validated URL
	case "darwin":
		cmd = exec.CommandContext(ctx, "open", u.String()) //nolint:gosec // G204: fixed program, validated URL
	default:
		cmd = exec.CommandContext(ctx, "xdg-open", u.String()) //nolint:gosec // G204: fixed program, validated URL
	}
	return cmd.Start()
}
