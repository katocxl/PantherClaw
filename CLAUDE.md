# Notes for AI coding sessions (Claude Code)

## There is no CI: every task is finished and verified locally, then pushed

CI, pull requests and the G1 review are switched off for development speed ([EX-004](docs/security/GATES_AND_REVIEW.md#4-exceptions), founder decision 2026-10-09). Nothing runs after a push, so the local checks are the only gate. For **every** task:

1. Do the work locally, on `main` (or a short-lived local branch merged into `main` before pushing).
2. Run all three checks and make sure each one passes. They take minutes, so run them in the background:
   - `task check` (format, headers, lint, unit tests, workflow lint, secret scan);
   - `task test:integration` (start the test cluster first with `task up PROFILE=test`; it listens on 127.0.0.1:5433);
   - `task trace` (every hardening rule and threat due by the current milestone has a test).
3. Commit with a [Conventional Commit](https://www.conventionalcommits.org/) message.
4. `git fetch`, rebase onto `origin/main` if anything came in (then run the checks again), and push to `main` as a fast-forward. Never force-push `main`.

Never push with a failing or skipped check, and never weaken a test or an `HR-###` rule to make one pass. A task is done only when it is committed **and** pushed. If a check cannot run (for example Docker is down), stop and say so instead of pushing.

Without a global Task install, run `go tool -modfile=tools/pins/task/go.mod task <name>`. On Windows run it from Git Bash, not PowerShell, which splits the `-modfile` argument.

## Where the plan lives

Start each session with [docs/BUILD_GUIDE.md](docs/BUILD_GUIDE.md) §0–§4 and the current milestone's G0 brief in [docs/g0/](docs/g0/). Binding rules are in [docs/security/HARDENING_RULES.md](docs/security/HARDENING_RULES.md). Implement only what the brief covers, and ask the founder about any security decision it leaves open. [CONTRIBUTING.md](CONTRIBUTING.md) has the conventions.
