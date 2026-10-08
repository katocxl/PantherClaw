// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package pclaw implements the pclaw command-line interface (M2: login and
// tenancy administration). cmd/pclaw only wires the process.
//
// Authentication: `pclaw login` stores a CLI session (ADR-0016); every
// command refreshes the access token when needed, signing the refresh with
// the device key. Automation can instead set PANTHERCLAW_SERVER and
// PANTHERCLAW_API_KEY (a pck_ key).
package pclaw

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"

	"connectrpc.com/connect/v2"

	"github.com/katocxl/pantherclaw/internal/platform/httpx"
	"github.com/katocxl/pantherclaw/internal/platform/version"
)

// Env reads environment variables (os.LookupEnv in production).
type Env func(string) (string, bool)

// Options are the process-level dependencies.
type Options struct {
	// OpenBrowser opens a URL in the user's browser (nil: never).
	OpenBrowser func(context.Context, string) error
	// HTTPClient overrides the HTTP client (tests).
	HTTPClient *http.Client
}

type app struct {
	stdout, stderr io.Writer
	env            Env
	http           *http.Client
	openBrowser    func(context.Context, string) error
}

var errUsage = errors.New("usage")

type command struct {
	usage string
	run   func(context.Context, *app, []string) error
}

// commands maps "group verb" (or a single word) to its implementation.
var commands = map[string]command{
	"login":  {"login --server URL --org ID [--invitation TOKEN] [--idp NAME] [--no-browser]", login},
	"logout": {"logout", logout},
	"whoami": {"whoami", whoami},
}

func usageText() string {
	var b strings.Builder
	b.WriteString("pclaw — PantherClaw command line\n\nUsage:\n")
	names := make([]string, 0, len(commands))
	for n := range commands {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		b.WriteString("  pclaw " + commands[n].usage + "\n")
	}
	b.WriteString("  pclaw version\n\nAutomation: set PANTHERCLAW_SERVER and PANTHERCLAW_API_KEY instead of logging in.\n")
	return b.String()
}

// Run executes pclaw and returns the exit code.
func Run(ctx context.Context, args []string, stdout, stderr io.Writer, env Env, opts Options) int {
	a := &app{stdout: stdout, stderr: stderr, env: env, http: opts.HTTPClient, openBrowser: opts.OpenBrowser}
	if a.http == nil {
		// Only the configured server is contacted; no redirects (HR-070).
		a.http = httpx.NewControlClient(httpx.ControlConfig{Timeout: 30 * time.Second})
	}
	if len(args) == 0 {
		_, _ = fmt.Fprint(stderr, usageText())
		return 2
	}
	if args[0] == "version" || args[0] == "--version" {
		_, _ = fmt.Fprintln(stdout, version.Get().String("pclaw"))
		return 0
	}
	cmd, rest, ok := lookup(args)
	if !ok {
		_, _ = fmt.Fprint(stderr, usageText())
		return 2
	}
	err := cmd.run(ctx, a, rest)
	switch {
	case err == nil:
		return 0
	case errors.Is(err, flag.ErrHelp):
		return 0
	case errors.Is(err, errUsage):
		_, _ = fmt.Fprintln(stderr, "usage: pclaw "+cmd.usage)
		return 2
	default:
		_, _ = fmt.Fprintln(stderr, "pclaw: "+describe(err))
		return 1
	}
}

func lookup(args []string) (command, []string, bool) {
	if len(args) >= 2 {
		if c, ok := commands[args[0]+" "+args[1]]; ok {
			return c, args[2:], true
		}
	}
	c, ok := commands[args[0]]
	return c, args[1:], ok
}

// describe turns RPC errors into one readable line.
func describe(err error) string {
	var ce *connect.Error
	if errors.As(err, &ce) {
		return strings.ReplaceAll(strings.ToLower(ce.Code().String()), "_", " ") + ": " + ce.Message()
	}
	return err.Error()
}
