# Notes for AI coding sessions (Claude Code)

## Every task ends as a pull request that the session lands itself

There is no CI ([EX-004](docs/security/GATES_AND_REVIEW.md#4-exceptions), founder decisions 2026-10-09 and 2026-10-10). GitHub runs nothing on a pull request: no checks, no security scans, no AI review. `main` accepts changes only through a pull request. Each session lands its own pull request as the last step of its task, with `tools/scripts/land.sh`, so finished work never piles up and conflicts stay small. Several sessions may work at the same time; [docs/PARALLEL_WORK.md](docs/PARALLEL_WORK.md) has the details. In short:

1. Work in your own worktree, on your own branch, starting from the latest `origin/main`: `git fetch origin`, then `git switch -c <type>/<slug> origin/main` (in a desktop worktree that already has a `claude/…` branch, run `git rebase origin/main` before your first commit). Never commit on `main`. Start the next task only after the previous one landed, from the new `origin/main`; build on an unlanded pull request's branch only when it waits for the founder (step 3).
2. Commit with Conventional Commit messages. While you work, run `task check`, and `task test:integration` (test cluster on 127.0.0.1:5433; `task up PROFILE=test`) when you touch database, server, gateway or end-to-end code. Run long commands in the background.
3. Push your branch and open a pull request with `gh pr create --base main`. The description says what changed and which checks ran with their result. If it needs a founder decision, open it with `--draft` and ask the founder in chat: a G0 brief or ADR whose questions are not answered, a security decision the brief leaves open, or a change to the text of an `HR-###` rule or a `T-###` threat. A draft never lands; once the founder agrees, `gh pr ready <n>`.
4. Land it: `tools/scripts/land.sh` (or `task land`). It merges `origin/main` into your branch, runs `task check`, `task test:integration` (unless only docs changed) and `task trace` on the result, pushes, and squash-merges the pull request pinned to exactly the commit that passed, starting again if `main` moved meanwhile. When it stops (a conflict, a failing check, a check that cannot run because Docker is down), fix what it says, commit, and run it again. If you cannot fix it, leave the pull request open and tell the founder why.
5. Report the landed pull request to the founder and take the next task.

Land only your own pull requests, only with `land.sh`. Never push to `main`, never force-push a branch another pull request is built on, and never weaken a test or an `HR-###` rule to make a check pass.

Without a global Task install, run `go tool -modfile=tools/pins/task/go.mod task <name>`. On Windows run it from Git Bash, not PowerShell, which splits the `-modfile` argument.

## Where the plan lives

Start each session with [docs/BUILD_GUIDE.md](docs/BUILD_GUIDE.md) §0–§4 and the current milestone's G0 brief in [docs/g0/](docs/g0/). Binding rules are in [docs/security/HARDENING_RULES.md](docs/security/HARDENING_RULES.md). Implement only what the brief covers, and ask the founder about any security decision it leaves open. [CONTRIBUTING.md](CONTRIBUTING.md) has the conventions.
