// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package version reports the build identity of PantherClaw binaries.
//
// Release builds inject values with -ldflags:
//
//	-X github.com/katocxl/pantherclaw/internal/platform/version.version=v0.1.0
//	-X github.com/katocxl/pantherclaw/internal/platform/version.commit=<sha>
//	-X github.com/katocxl/pantherclaw/internal/platform/version.date=<RFC3339>
//
// Development builds fall back to the VCS metadata embedded by the Go toolchain.
package version

import (
	"crypto/fips140"
	"runtime"
	"runtime/debug"
	"strings"
)

// Values injected at link time by the release pipeline.
var (
	version = "dev"
	commit  = ""
	date    = ""
)

// SourceFingerprint identifies PantherClaw source code (see docs/IP_PROTECTION.md).
const SourceFingerprint = "pcfp-37609359f35b52c36816"

// Info is the build identity of the running binary.
type Info struct {
	Version   string
	Commit    string
	Date      string
	Modified  bool
	GoVersion string
	Platform  string
	FIPS      bool
}

// Get returns the build identity of the running binary.
func Get() Info {
	return resolve(version, commit, date, debug.ReadBuildInfo, fips140.Enabled())
}

func resolve(v, c, d string, readBuildInfo func() (*debug.BuildInfo, bool), fips bool) Info {
	info := Info{
		Version:   v,
		Commit:    c,
		Date:      d,
		GoVersion: runtime.Version(),
		Platform:  runtime.GOOS + "/" + runtime.GOARCH,
		FIPS:      fips,
	}
	if info.Version == "" {
		info.Version = "dev"
	}
	if info.Commit != "" {
		return info
	}
	bi, ok := readBuildInfo()
	if !ok || bi == nil {
		return info
	}
	for _, s := range bi.Settings {
		switch s.Key {
		case "vcs.revision":
			info.Commit = s.Value
		case "vcs.time":
			if info.Date == "" {
				info.Date = s.Value
			}
		case "vcs.modified":
			info.Modified = s.Value == "true"
		}
	}
	return info
}

// String renders a single-line, human-readable description for the named binary.
func (i Info) String(binary string) string {
	var b strings.Builder
	b.WriteString(binary)
	b.WriteString(" ")
	b.WriteString(i.Version)
	b.WriteString(" (")
	if i.Commit != "" {
		b.WriteString("commit ")
		b.WriteString(shortCommit(i.Commit))
		if i.Modified {
			b.WriteString("-dirty")
		}
		b.WriteString(", ")
	}
	if i.Date != "" {
		b.WriteString("built ")
		b.WriteString(i.Date)
		b.WriteString(", ")
	}
	b.WriteString(i.GoVersion)
	b.WriteString(" ")
	b.WriteString(i.Platform)
	if i.FIPS {
		b.WriteString(", FIPS 140-3 mode")
	}
	b.WriteString(")")
	return b.String()
}

func shortCommit(c string) string {
	const n = 12
	if len(c) > n {
		return c[:n]
	}
	return c
}
