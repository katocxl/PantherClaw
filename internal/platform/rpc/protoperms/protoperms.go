// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package protoperms reads the "// permission: <name>" declarations from the
// proto sources (BUILD_GUIDE §3.2), so tests can check them against the
// permission catalog and the server's procedure table. It is test support
// only: the server never parses protos at runtime.
package protoperms

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

var (
	packageLine = regexp.MustCompile(`^\s*package\s+([a-z0-9_.]+)\s*;`)
	serviceLine = regexp.MustCompile(`^\s*service\s+(\w+)\s*\{`)
	rpcLine     = regexp.MustCompile(`^\s*rpc\s+(\w+)\s*\(`)
	permLine    = regexp.MustCompile(`^\s*//\s*permission:\s*([a-z][a-z0-9_.]*)\s*$`)
)

// Declared walks root and returns procedure ("/pkg.Service/Method") →
// declared permission for every rpc. An rpc without a declaration is an
// error.
func Declared(root string) (map[string]string, error) {
	out := map[string]string{}
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() || filepath.Ext(path) != ".proto" {
			return err
		}
		f, err := os.Open(path) //nolint:gosec // G304: test support reading the repository's proto tree
		if err != nil {
			return err
		}
		defer func() { _ = f.Close() }()
		var pkg, service string
		var comments []string
		s := bufio.NewScanner(f)
		for s.Scan() {
			line := s.Text()
			if m := packageLine.FindStringSubmatch(line); m != nil {
				pkg = m[1]
			}
			if m := serviceLine.FindStringSubmatch(line); m != nil {
				service = m[1]
			}
			if strings.HasPrefix(strings.TrimSpace(line), "//") {
				comments = append(comments, line)
				continue
			}
			if m := rpcLine.FindStringSubmatch(line); m != nil {
				perm := ""
				for _, c := range comments {
					if pm := permLine.FindStringSubmatch(c); pm != nil {
						perm = pm[1]
					}
				}
				proc := "/" + pkg + "." + service + "/" + m[1]
				if perm == "" || pkg == "" || service == "" {
					return fmt.Errorf("%s: rpc %s has no '// permission:' declaration", path, proc)
				}
				out[proc] = perm
			}
			comments = comments[:0]
		}
		return s.Err()
	})
	if err != nil {
		return nil, err
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("protoperms: no rpc found under %s", root)
	}
	return out, nil
}
