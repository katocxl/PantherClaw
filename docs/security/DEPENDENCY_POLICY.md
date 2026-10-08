# PantherClaw — Dependency & Build Policy (SG07)

## 1. Principles

1. **Fewer dependencies is a security feature.** Prefer the Go standard library. Every direct dependency needs a written justification below before its first import.
2. **Pinned and verified.** Lockfiles are committed; installs are reproducible and verified against checksums.
3. **Cooldown.** New upstream releases are not adopted for 7 days (malicious releases are usually caught within that window). Security fixes for actively exploited vulnerabilities may skip the cooldown with a recorded reason.
4. **Reachability-aware.** Go vulnerabilities are judged by `govulncheck` call-graph reachability; unreachable findings are tracked, not ignored.
5. **No copyleft in shipped artifacts.** Allowed licences for code linked into released binaries/SDKs: Apache-2.0, MIT, BSD-2/3-Clause, ISC, MPL-2.0 (file-level, unmodified), Unicode-DFS, CC0, 0BSD. Disallowed: GPL/AGPL/LGPL (except standalone dev tools never shipped, e.g. golangci-lint, k6), SSPL, BSL/FSL from others, unknown.

## 2. Sources

| Ecosystem | Source | Verification | Lockfile |
|---|---|---|---|
| Go | `proxy.golang.org` (default `GOPROXY`), `sum.golang.org` | `go mod verify`, `GOFLAGS=-mod=readonly`, `GONOSUMDB` unset | `go.sum` |
| Go dev tools | `tool` directives in `tools/go.mod` (run with `go tool -modfile=tools/go.mod`) | same | `tools/go.sum` |
| Python SDK | PyPI via `uv` | `uv lock` with hashes, `uv sync --locked`, `exclude-newer = "7 days"` | `uv.lock` |
| TypeScript SDK | npm registry via pnpm (pinned through `packageManager` + Corepack) | `pnpm install --frozen-lockfile`, `minimumReleaseAge: 10080`, lifecycle scripts blocked except allowlist | `pnpm-lock.yaml` |
| GitHub Actions | GitHub Marketplace | **full commit SHA pins** (repository policy enforces), version comment | workflow files |
| Containers | Distroless / official images | **digest pins** | Dockerfiles, compose |
| Binaries in CI (gitleaks, buf, etc.) | Official GitHub releases | SHA-256 checksum verified in workflow | workflow files |

Excluded: **Trivy and `aquasecurity/trivy-action`** (supply-chain compromise, March 2026, CVE-2026-33634) — replaced by OSV-Scanner and Scorecard. `tj-actions/changed-files` (2025 compromise) — use `dorny/paths-filter`.

## 3. Approved direct dependencies (Go core)

| Module | Purpose | Licence | Justification |
|---|---|---|---|
| `github.com/jackc/pgx/v5` | PostgreSQL driver + pool | MIT | De-facto standard; needed for COPY-free, typed, context-aware access |
| `github.com/pressly/goose/v3` | Migrations | MIT | Embedded SQL migrations, simple, no DSL |
| `github.com/riverqueue/river` (+ `riverpgxv5`) | Postgres job queue / outbox | MPL-2.0 | Transactional enqueue (InsertTx) |
| `connectrpc.com/connect/v2` (+ `otelconnect`, `grpchealth`, `validate`) | RPC framework | Apache-2.0 | One handler for gRPC/Connect JSON |
| `buf.build/go/protovalidate` | Contract validation (CEL) | Apache-2.0 | Declarative input validation |
| `google.golang.org/protobuf` | Protobuf runtime | BSD-3 | Required by Connect |
| `github.com/google/cel-go` | Policy/detection expressions | Apache-2.0 | Safe, typed, cost-bounded expressions |
| `github.com/go-jose/go-jose/v4` (≥ 4.1.5) | JWS/JWT/JWK, thumbprints | Apache-2.0 | Algorithm allowlists; RFC 7638 |
| `github.com/coreos/go-oidc/v3` | OIDC relying party | Apache-2.0 | ID token verification, discovery |
| `golang.org/x/oauth2` | OAuth2 flows | BSD-3 | Auth code, device flow |
| `github.com/go-webauthn/webauthn` | WebAuthn step-up | BSD-3 | Maintained server-side WebAuthn |
| `github.com/modelcontextprotocol/go-sdk` | MCP server/client | MIT/Apache | Official SDK |
| `go.opentelemetry.io/otel` (+ SDK, OTLP exporters) | Telemetry | Apache-2.0 | Standard |
| `github.com/google/uuid` | UUIDv7 | BSD-3 | Small, stable |
| `golang.org/x/text` | Unicode (confusables/NFC helpers) | BSD-3 | Canonicalization |
| `golang.org/x/sync` | errgroup/singleflight | BSD-3 | Concurrency helpers |

Test-only: `github.com/testcontainers/testcontainers-go` (MIT), `github.com/peterldowns/pgtestdb` (MIT), `pgregory.net/rapid` (MPL-2.0, property tests).
Dev tools (not shipped): golangci-lint (GPL-3.0, tool only), gofumpt, sqlc, buf, goose CLI, task, actionlint, govulncheck, osv-scanner, gitleaks, zizmor, Semgrep CE, goreleaser, syft, cosign, k6 (AGPL, tool only), schemathesis.

Adding a dependency: PR adds a row here (purpose, licence, maintenance status, alternatives considered, transitive count), passes dependency-review, and is called out in the G1 review.

## 4. Updates

- Dependabot: `gomod` (root, `tools/`, `sdk/go`), `uv`, `npm`, `github-actions`, `docker`; weekly; grouped minor/patch; `cooldown: default-days: 7`; security updates immediate.
- Major upgrades get their own PR with changelog review and full test run.
- Upstream releases with breaking module paths (e.g. connect-go v2) are adopted deliberately with an ADR note.

## 5. Vulnerability handling

| Severity (reachable) | Fix deadline | Exception max |
|---|---|---|
| Critical | 7 days | 7 days |
| High | 30 days | 30 days |
| Medium | 90 days | 30 days |
| Low | next routine update | — |

Unreachable vulnerabilities: tracked, fixed at next routine update. Released versions are re-scanned weekly (`nightly.yml`); new findings against a release create a private advisory and a patch release.

## 6. Build integrity

- Builds are reproducible from a tag: `-trimpath`, `-buildvcs=true`, pinned toolchain (`toolchain go1.27.1`), `CGO_ENABLED=0` for release binaries.
- Release artifacts: SBOM (SPDX + CycloneDX via syft), GitHub artifact attestations (build provenance) for binaries, checksums, SBOMs and images; container images also signed with cosign (keyless, Sigstore bundle).
- Publishing uses OIDC trusted publishing (PyPI, npm) bound to the protected `release` environment; no long-lived registry tokens exist.
- Users verify with `gh attestation verify` / `cosign verify`; `pclaw` self-update verifies attestations before replacing itself.
