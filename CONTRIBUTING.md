# Contributing to PantherClaw

## Status

PantherClaw is being built in the open under a source-available license. **Outside code contributions are not yet accepted**: the Contributor License Agreement ([CLA.md](CLA.md)) must be in place first. Issues with bug reports and design feedback are welcome. Security issues: see [SECURITY.md](SECURITY.md) — never file them publicly.

## How work happens (also for the maintainer)

All changes follow [docs/BUILD_GUIDE.md](docs/BUILD_GUIDE.md) and the gates in [docs/security/GATES_AND_REVIEW.md](docs/security/GATES_AND_REVIEW.md):

1. **G0 brief** exists for the milestone (scope, threat slice, constraints, tests).
2. Branch from `main` (`feat/…`, `fix/…`, `docs/…`, `chore/…`, `sec/…`).
3. Every source file carries the SPDX + copyright header (`task license:fix`).
4. Tests first for security-relevant behavior; reference requirement IDs (`F###`, `PN-###`, `HR-###`, `T-###`) in test names or comments.
5. `task check` must pass locally (format, lint, unit tests, headers, secrets scan).
6. Open a PR with a [Conventional Commit](https://www.conventionalcommits.org/) title; complete the PR template security checklist.
7. CI (`ci-ok`) green + two independent AI reviews (Claude, CodeRabbit) addressed + human review (G1) → squash merge.

## Development setup

Windows, macOS and Linux are supported for development. Requirements: Go (toolchain pinned in `go.mod`), [Task](https://taskfile.dev), Docker, and for SDK work `uv` (Python) and `pnpm` via Corepack (TypeScript). Race detector, integration and signal tests run on Linux (`task test:linux` uses a container; CI is canonical).

```bash
task setup    # configure git hooks (.githooks) and build the pinned dev tools
task check    # fmt + lint + unit tests + license headers + secret scan
```

## Commit conventions

- Conventional Commits (`feat:`, `fix:`, `sec:`, `docs:`, `chore:`, `refactor:`, `test:`, `ci:`, `build:`).
- One logical change per PR; generated code committed alongside its source change.
- Never commit secrets, real customer data, or descriptions of unfixed vulnerabilities.
