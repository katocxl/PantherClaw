// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package cli holds the minimal command-line entry behavior shared by
// PantherClaw binaries while their real implementations are being built.
package cli

import (
	"errors"
	"flag"
	"fmt"
	"io"

	"github.com/katocxl/pantherclaw/internal/platform/version"
)

// Exit codes shared by all PantherClaw binaries.
const (
	ExitOK             = 0
	ExitNotImplemented = 1
	ExitUsage          = 2
)

// Stub runs a placeholder command: it supports `--version` / `version` and
// otherwise reports which milestone delivers the binary. It never starts a
// listener or touches the network.
func Stub(binary, milestone string, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet(binary, flag.ContinueOnError)
	fs.SetOutput(stderr)
	showVersion := fs.Bool("version", false, "print version information and exit")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return ExitOK
		}
		return ExitUsage
	}
	if *showVersion || (fs.NArg() == 1 && fs.Arg(0) == "version") {
		_, _ = fmt.Fprintln(stdout, version.Get().String(binary))
		return ExitOK
	}
	_, _ = fmt.Fprintf(stderr, "%s: not implemented yet (delivered in milestone %s, see docs/BUILD_GUIDE.md)\n", binary, milestone)
	return ExitNotImplemented
}
