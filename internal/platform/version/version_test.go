// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package version

import (
	"runtime"
	"runtime/debug"
	"strings"
	"testing"
)

func buildInfo(settings ...debug.BuildSetting) func() (*debug.BuildInfo, bool) {
	return func() (*debug.BuildInfo, bool) {
		return &debug.BuildInfo{Settings: settings}, true
	}
}

func noBuildInfo() (*debug.BuildInfo, bool) { return nil, false }

func TestResolve(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		v, c, d       string
		readBuildInfo func() (*debug.BuildInfo, bool)
		want          Info
	}{
		{
			name:          "linker values take precedence over VCS metadata",
			v:             "v0.1.0",
			c:             "0123456789abcdef0123",
			d:             "2026-10-08T00:00:00Z",
			readBuildInfo: buildInfo(debug.BuildSetting{Key: "vcs.revision", Value: "ignored"}),
			want:          Info{Version: "v0.1.0", Commit: "0123456789abcdef0123", Date: "2026-10-08T00:00:00Z"},
		},
		{
			name: "falls back to VCS metadata",
			v:    "dev",
			readBuildInfo: buildInfo(
				debug.BuildSetting{Key: "vcs.revision", Value: "abc"},
				debug.BuildSetting{Key: "vcs.time", Value: "2026-10-08T12:00:00Z"},
				debug.BuildSetting{Key: "vcs.modified", Value: "true"},
			),
			want: Info{Version: "dev", Commit: "abc", Date: "2026-10-08T12:00:00Z", Modified: true},
		},
		{
			name:          "empty version defaults to dev",
			readBuildInfo: noBuildInfo,
			want:          Info{Version: "dev"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := resolve(tt.v, tt.c, tt.d, tt.readBuildInfo, false)
			tt.want.GoVersion = runtime.Version()
			tt.want.Platform = runtime.GOOS + "/" + runtime.GOARCH
			if got != tt.want {
				t.Fatalf("resolve() = %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestInfoString(t *testing.T) {
	t.Parallel()

	full := Info{
		Version: "v0.1.0", Commit: "0123456789abcdef0123", Date: "2026-10-08T00:00:00Z",
		Modified: true, GoVersion: "go1.27.1", Platform: "linux/amd64", FIPS: true,
	}
	want := "pantherclaw-server v0.1.0 (commit 0123456789ab-dirty, built 2026-10-08T00:00:00Z, go1.27.1 linux/amd64, FIPS 140-3 mode)"
	if got := full.String("pantherclaw-server"); got != want {
		t.Fatalf("String() = %q, want %q", got, want)
	}

	minimal := Info{Version: "dev", GoVersion: "go1.27.1", Platform: "windows/amd64"}
	if got := minimal.String("pclaw"); got != "pclaw dev (go1.27.1 windows/amd64)" {
		t.Fatalf("String() = %q", got)
	}
}

func TestGetReturnsRuntimeIdentity(t *testing.T) {
	t.Parallel()

	info := Get()
	if info.Version == "" || info.GoVersion != runtime.Version() {
		t.Fatalf("unexpected info: %+v", info)
	}
	if !strings.Contains(info.String("x"), runtime.GOOS) {
		t.Fatalf("String() should include the platform: %q", info.String("x"))
	}
}

func TestSourceFingerprintFormat(t *testing.T) {
	t.Parallel()

	if !strings.HasPrefix(SourceFingerprint, "pcfp-") || len(SourceFingerprint) != 25 {
		t.Fatalf("unexpected fingerprint format %q", SourceFingerprint)
	}
}
