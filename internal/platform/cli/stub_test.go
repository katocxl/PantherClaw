// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package cli

import (
	"bytes"
	"strings"
	"testing"
)

func TestStub(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		args       []string
		wantCode   int
		wantStdout string
		wantStderr string
	}{
		{name: "version flag", args: []string{"--version"}, wantCode: ExitOK, wantStdout: "pclaw "},
		{name: "version subcommand", args: []string{"version"}, wantCode: ExitOK, wantStdout: "pclaw "},
		{name: "help", args: []string{"-h"}, wantCode: ExitOK, wantStderr: "-version"},
		{name: "no args", args: nil, wantCode: ExitNotImplemented, wantStderr: "milestone M6"},
		{name: "unknown subcommand", args: []string{"serve"}, wantCode: ExitNotImplemented, wantStderr: "not implemented"},
		{name: "unknown flag", args: []string{"--bogus"}, wantCode: ExitUsage, wantStderr: "bogus"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var stdout, stderr bytes.Buffer
			code := Stub("pclaw", "M6", tt.args, &stdout, &stderr)
			if code != tt.wantCode {
				t.Fatalf("code = %d, want %d (stderr=%q)", code, tt.wantCode, stderr.String())
			}
			if !strings.Contains(stdout.String(), tt.wantStdout) {
				t.Fatalf("stdout = %q, want substring %q", stdout.String(), tt.wantStdout)
			}
			if !strings.Contains(stderr.String(), tt.wantStderr) {
				t.Fatalf("stderr = %q, want substring %q", stderr.String(), tt.wantStderr)
			}
		})
	}
}
