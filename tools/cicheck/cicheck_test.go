// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package cicheck

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

var root = filepath.Join("..", "..")

func workflows(t *testing.T) map[string]string {
	t.Helper()
	paths, err := filepath.Glob(filepath.Join(root, ".github", "workflows", "*.yml"))
	if err != nil || len(paths) == 0 {
		t.Fatalf("no workflows found: %v", err)
	}
	out := map[string]string{}
	for _, p := range paths {
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		out[filepath.Base(p)] = string(b)
	}
	return out
}

var (
	usesLine   = regexp.MustCompile(`(?m)^\s*-?\s*uses:\s*(\S+)`)
	pinnedUses = regexp.MustCompile(`^[\w.-]+/[\w./-]+@[0-9a-f]{40}$`)
)

// TestHR130_WorkflowsAreHardened: no pull_request_target, default
// permissions {}, every action pinned by full commit SHA, and checkout never
// persists credentials.
func TestHR130_WorkflowsAreHardened(t *testing.T) {
	for name, wf := range workflows(t) {
		if strings.Contains(code(wf), "pull_request_target") {
			t.Errorf("%s: uses pull_request_target", name)
		}
		if !regexp.MustCompile(`(?m)^permissions:\s*\{\}\s*$`).MatchString(wf) {
			t.Errorf("%s: top-level permissions must be {}", name)
		}
		for _, m := range usesLine.FindAllStringSubmatch(wf, -1) {
			ref := m[1]
			if strings.HasPrefix(ref, "./") {
				continue
			}
			if !pinnedUses.MatchString(ref) {
				t.Errorf("%s: action %q is not pinned to a full commit SHA", name, ref)
			}
		}
		// Each checkout step must set persist-credentials: false.
		lines := strings.Split(wf, "\n")
		for i, l := range lines {
			if !strings.Contains(l, "uses: actions/checkout@") {
				continue
			}
			found := false
			for j := i + 1; j < len(lines) && j <= i+6; j++ {
				if strings.Contains(lines[j], "persist-credentials: false") {
					found = true
					break
				}
				if strings.Contains(lines[j], "- uses:") || strings.Contains(lines[j], "- name:") {
					break
				}
			}
			if !found {
				t.Errorf("%s:%d: actions/checkout without persist-credentials: false", name, i+1)
			}
		}
	}
}

// TestHR131_ReleaseIsHardened: the publishing job runs in the protected
// release environment, with harden-runner in block mode, OIDC only and
// provenance attestations.
func TestHR131_ReleaseIsHardened(t *testing.T) {
	wf := workflows(t)["release.yml"]
	if wf == "" {
		t.Fatal("release.yml missing")
	}
	for _, want := range []string{
		"egress-policy: block",
		"actions/attest-build-provenance@",
		"id-token: write",
		"tags: [\"v*\"]",
	} {
		if !strings.Contains(wf, want) {
			t.Errorf("release.yml: missing %q", want)
		}
	}
	if !regexp.MustCompile(`(?m)^\s+environment:\s*(\n\s+name:\s*)?release\b`).MatchString(wf) &&
		!strings.Contains(wf, "name: release") {
		t.Error("release.yml: publishing does not use the protected release environment")
	}
	for _, banned := range []string{"NPM_TOKEN", "PYPI_TOKEN", "TWINE_PASSWORD", "secrets.GH_PAT"} {
		if strings.Contains(wf, banned) {
			t.Errorf("release.yml: long-lived registry credential %q used; publishing must use OIDC", banned)
		}
	}
}

// TestHR132_DependencyGates: govulncheck, OSV-Scanner and dependency review
// run in CI, Dependabot has a 7-day cooldown, and Trivy is never used.
func TestHR132_DependencyGates(t *testing.T) {
	all := workflows(t)
	ci := all["ci.yml"]
	for _, want := range []string{"govulncheck", "osv-scanner", "actions/dependency-review-action@"} {
		if !strings.Contains(ci, want) {
			t.Errorf("ci.yml: missing %s gate", want)
		}
	}
	for name, wf := range all {
		if strings.Contains(strings.ToLower(code(wf)), "trivy") {
			t.Errorf("%s: references Trivy (excluded after the March 2026 compromise)", name)
		}
	}
	dep, err := os.ReadFile(filepath.Join(root, ".github", "dependabot.yml"))
	if err != nil {
		t.Fatal(err)
	}
	ecosystems := strings.Count(string(dep), "package-ecosystem:")
	cooldowns := strings.Count(string(dep), "default-days: 7")
	if ecosystems == 0 || cooldowns < ecosystems {
		t.Errorf("dependabot.yml: %d ecosystems but %d 7-day cooldowns", ecosystems, cooldowns)
	}
}

// code returns the workflow without YAML comment lines or trailing comments,
// so prose that names a banned feature does not count as using it.
func code(wf string) string {
	var b strings.Builder
	for _, l := range strings.Split(wf, "\n") {
		if strings.HasPrefix(strings.TrimSpace(l), "#") {
			continue
		}
		if i := strings.Index(l, " #"); i >= 0 {
			l = l[:i]
		}
		b.WriteString(l)
		b.WriteByte('\n')
	}
	return b.String()
}
