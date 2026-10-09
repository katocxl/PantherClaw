// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package actionir_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/katocxl/pantherclaw/internal/actionir"
)

// TestHR187_PathsHaveOneSpelling: every spelling of a directory normalizes
// to one form, and the forms Windows treats specially are refused.
func TestHR187_PathsHaveOneSpelling(t *testing.T) {
	for in, want := range map[string]string{
		`C:\Users\dev\repo`:              `C:\Users\dev\repo`,
		`c:/Users/dev/repo/`:             `C:\Users\dev\repo`,
		`c:\Users\.\dev\..\dev\\repo`:    `C:\Users\dev\repo`,
		`C:\..\..\Windows`:               `C:\Windows`,
		`C:/`:                            `C:\`,
		`C:\a b\c`:                       `C:\a b\c`,
		`\\fileserver\share\team\..\x`:   `\\fileserver\share\x`,
		`//fileserver/share`:             `\\fileserver\share`,
		`\\fileserver\share\..\..\data`:  `\\fileserver\share\data`,
		`/home/dev/./repo/../repo//src/`: `/home/dev/repo/src`,
		`/../..`:                         `/`,
		`/`:                              `/`,
		`C:\Users\Jürgen\répertoire`:     `C:\Users\Jürgen\répertoire`,
	} {
		got, err := actionir.NormalizePath(in)
		if err != nil || got != want {
			t.Errorf("NormalizePath(%q) = %q, %v; want %q", in, got, err, want)
		}
		if again, err := actionir.NormalizePath(got); err != nil || again != got {
			t.Errorf("NormalizePath is not idempotent on %q: %q, %v", got, again, err)
		}
	}
	for _, in := range []string{
		"", "repo", `.\repo`, `C:repo`, `C:`,
		`\\?\C:\Windows`, `\\.\PhysicalDrive0`, `//?/C:/x`, `\\server`, `\\server\`, `\\server\..\x`,
		`C:\repo\file.txt:hidden`, `C:\repo\x::$DATA`,
		`C:\repo.\x`, `C:\repo \x`, `C:\repo\...`, `\\server\share.\x`,
		"/home/dev\x00/x", "C:\\a\nb", "/a\u202eb", "/a\u200bb",
		"/" + strings.Repeat("a", actionir.MaxPath),
		"/a\xffb",
	} {
		if got, err := actionir.NormalizePath(in); !errors.Is(err, actionir.ErrAmbiguous) {
			t.Errorf("NormalizePath(%q) = %q, %v; want ambiguous", in, got, err)
		}
	}
}
