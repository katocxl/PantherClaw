# Notes for AI coding sessions (Claude Code)

## There is no CI: every task is finished and verified locally, then pushed

CI, pull requests and the G1 review are switched off for development speed ([EX-004](docs/security/GATES_AND_REVIEW.md#4-exceptions), founder decision 2026-10-09). Nothing runs after a push, so the local checks are the only gate. Several sessions may work at the same time, so every task follows the parallel-work protocol in [docs/PARALLEL_WORK.md](docs/PARALLEL_WORK.md). Read it before you start. In short:

1. Work in your own worktree, on your own branch: `tools/scripts/flow.sh start <slug>` creates `task/<slug>` from the local `integration` branch. Never commit on `main` or `integration`, and never check them out.
2. Check what other sessions are changing with `tools/scripts/flow.sh status`. Keep tasks small, and keep your edits to shared files small.
3. Commit on your task branch. Pick up others' work with `tools/scripts/flow.sh sync`.
4. Finish with `tools/scripts/flow.sh land`. It rebases onto `integration`, runs `task check`, `task test:integration` (test cluster on 127.0.0.1:5433; `task up PROFILE=test`) and `task trace`, then moves `integration` and `origin/main` forward to your commit. It takes minutes, so run it in the background.

A task is done only when `land` prints `landed`. Never push with a failing or skipped check, never force-push, and never weaken a test or an `HR-###` rule to make one pass. If a check cannot run (for example Docker is down), stop and say so instead of pushing.

Without a global Task install, run `go tool -modfile=tools/pins/task/go.mod task <name>`. On Windows run it, and `flow.sh`, from Git Bash, not PowerShell, which splits the `-modfile` argument.

## Where the plan lives

Start each session with [docs/BUILD_GUIDE.md](docs/BUILD_GUIDE.md) §0–§4 and the current milestone's G0 brief in [docs/g0/](docs/g0/). Binding rules are in [docs/security/HARDENING_RULES.md](docs/security/HARDENING_RULES.md). Implement only what the brief covers, and ask the founder about any security decision it leaves open. [CONTRIBUTING.md](CONTRIBUTING.md) has the conventions.
