# ADR-0008 — Scanning toolchain without CodeQL or Trivy

**Status:** Accepted (2026-10-08)

**Decision.** PR gates: golangci-lint v2 (including gosec, staticcheck, depguard, forbidigo), Opengrep/Semgrep CE with project rules, govulncheck, OSV-Scanner, dependency-review (vulnerabilities + licence allowlist), gitleaks (pinned, checksum-verified binary) plus GitHub push protection, zizmor (workflows), licence-header check, and the product invariant/race/tenancy/adversarial suites. Nightly: fuzzing, Schemathesis, k6, re-scan of released versions. Weekly: OpenSSF Scorecard. A single required status check, `ci-ok`, aggregates everything.

**Why not CodeQL:** its free licence covers OSI-licensed codebases; the core is BSL (ADR-0007). **Why not Trivy:** the Trivy GitHub Action and releases were compromised in March 2026 (CVE-2026-33634).

**Consequences.** Less semantic data-flow analysis than CodeQL, compensated by gosec, custom Semgrep rules for our risky APIs, fuzzing and the adversarial suite. Upgrade path: GitHub Advanced Security if code scanning becomes necessary.
