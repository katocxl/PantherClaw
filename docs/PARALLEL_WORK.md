# Parallel work: several AI sessions on one repository

Read this before you start any task in this repository. It applies to every Claude Code session (desktop tab, terminal or IDE) and to people. It works together with the pull-request rule in [CLAUDE.md](../CLAUDE.md) ([EX-004](security/GATES_AND_REVIEW.md#4-exceptions)).

## How work reaches `main`

Every task ends as a pull request, and the session that wrote it lands it as soon as it is done, with [`tools/scripts/land.sh`](../tools/scripts/land.sh) (founder decision 2026-10-10). GitHub runs no checks on it; `land.sh` runs the local checks on the result of merging the latest `main` and merges only the commit that passed them. Landing every task right away keeps `main` current, so the next task starts from it and conflicts stay small. Two tasks can still change the same lines; the second one to land merges `main`, resolves the conflict on its own branch and checks again.

| Branch | What it is | Rules |
|---|---|---|
| `main` | What is on GitHub. | Changes only through a merged pull request (the `main` ruleset requires one), merged by `land.sh`. Never commit on it or push to it. |
| your branch | One task: `feat/…`, `fix/…`, `docs/…`, or the `claude/…` branch the desktop app gave your worktree. | One session per branch, in its own worktree. Push it, open a pull request, land it. |

## The loop for every task

1. **Get a worktree of your own.** The desktop app gives each session one under `.claude/worktrees/`. Never work in another session's worktree: two sessions in one folder overwrite each other's files. A new worktree lacks the git-ignored `deploy/compose/.env` (the test database password), so copy it from the main checkout before you run the integration tests: `cp "$(git worktree list | head -1 | cut -d' ' -f1)/deploy/compose/.env" deploy/compose/.env`.
2. **Look at what is in flight:** `gh pr list` shows the open pull requests and `gh pr diff <n> --name-only` the files each one changes. If your task needs the same files as one that is about to land, wait for it to land and start from the new `main`; otherwise put your code in new files and keep your edits to the shared files to a few lines.
3. **Start** from the latest `origin/main`: `git fetch origin`, then `git switch -c <type>/<slug> origin/main`. In a desktop worktree that already has a `claude/…` branch, run `git rebase origin/main` before your first commit. Build on another pull request's branch (a stacked pull request) only when that one cannot land yet because it is a draft waiting for the founder.
4. **Work in small steps.** A task should take about 30–60 minutes of agent time and stay under about 600 lines of non-generated diff ([BUILD_GUIDE](BUILD_GUIDE.md) §0). Split bigger work into several pull requests. Commit often.
5. **Check locally while you work.** There is no CI, so the local checks are the only test the code gets:
   - `task check` (format, headers, lint, unit tests, secret scan);
   - `task test:integration` when you touched database, server, gateway or end-to-end code (cluster on `127.0.0.1:5433`; start it with `task up PROFILE=test`);
   - `task trace` when you added or renamed `HR-###` or `T-###` tests.

   They take minutes, so run them in the background. Never weaken a test or an `HR-###` rule to make one pass.
6. **Open the pull request:** `git push -u origin HEAD`, then `gh pr create --base main`. Say what changed and which checks ran with their result. If it needs a founder decision, open it as a draft (`--draft`) and ask the founder: a G0 brief or ADR whose questions are not answered, a security decision the brief leaves open, or a change to the text of an `HR-###` rule or a `T-###` threat. Once the founder agrees, `gh pr ready <n>`.
7. **Land it:** `tools/scripts/land.sh` (or `task land`), described below. Then report the landed pull request to the founder and start the next task from the new `origin/main`.

## Landing

`tools/scripts/land.sh` refuses a draft, a pull request whose base is not `main` (land that base first), and uncommitted changes. Then it:

1. merges `origin/main` into your branch when the branch lacks it; a conflict stops it (see below), and you commit the resolution and run it again;
2. runs `task check`, `task test:integration` (unless only `docs/` or Markdown files changed) and `task trace` on that result; a failing check, or one that cannot run (Docker down, no `deploy/compose/.env`), stops it;
3. pushes the checked commit (never forced) and, if `main` has not moved since, squash-merges the pull request with `--match-head-commit`, so GitHub merges exactly the commit that passed; if `main` moved, it starts again from step 1 (up to three times).

`--dry-run` runs the same checks without pushing or merging. When it stops and you cannot fix the cause, leave the pull request open and tell the founder why. Land only your own pull requests, and only with `land.sh`.

## Keeping an open pull request up to date

`land.sh` merges `origin/main` into your branch itself. To update a pull request you are not landing yet (a draft, or one another branch builds on), merge `origin/main` into your branch, resolve the conflicts, run the checks again and push. Merging keeps branches stacked on yours intact; never force-push a branch another pull request is built on. When a stacked pull request's base lands, GitHub retargets the next one to `main` and deletes the merged branch; its session then lands it with `land.sh`, which merges the new `main` in first.

## Shared files: where conflicts come from

These files are touched by many tasks. Keep your edits to them small and prefer new files:

- server wiring: `internal/server/server.go`, `procedures.go`, `config.go` (add a `register…` function or a `wiring_<area>.go` file instead of growing `apiHandler`);
- the permission and role catalog: `internal/tenancy/domain/permissions.go`, `roles.go`;
- generated code: `internal/gen/**` (from `queries/*.sql`, `proto/**`, `sqlc.yaml`, `buf.gen.yaml`);
- `go.mod` / `go.sum`, `Taskfile.yml`;
- numbered things: `migrations/000NN_*.sql`, `HR-###` in [HARDENING_RULES](security/HARDENING_RULES.md), `T-###` in [THREAT_MODEL](security/THREAT_MODEL.md), proto field numbers;
- G0 briefs in `docs/g0/` and [FEATURES.md](FEATURES.md).

**Numbers.** Use the range the founder or the G0 brief gave your task. If there is none, take the next number that is free on `main` *and* in every open pull request (`gh pr list`, then look at their diffs), and say which numbers you took in the pull request description. A duplicate migration version makes `task test:integration` fail once both are merged; renumber in the pull request that is not merged yet.

## Resolving a conflict

- **Generated code** (`internal/gen/**`): take either side, run `task gen` (it regenerates and fixes headers), and `git add` the result. Never hand-merge generated files.
- **`go.sum`**: take either side, then `go mod tidy`.
- **Everything else**: keep both sides' intent. Never drop another task's change to make yours fit. If you cannot tell what the other change needs, stop and ask the founder.
- Then commit the merge, run the checks again and push.

## Shared resources

- **Test database:** all sessions share the cluster on `127.0.0.1:5433`. Each test creates its own database, so concurrent runs are safe. If it is down, `task up PROFILE=test`. Never stop, reset or wipe containers another session may be using.
- **Lint:** golangci-lint keeps one lock per machine; `task lint` waits for another session's run instead of failing.
- **Ports:** if you run a local server or gateway, use ports no other session uses.
- **Docker, the founder's credentials and GitHub settings** are shared. Change none of them unless the founder asks.

## What never happens

- No pushes to `main`, and no merges except `land.sh` landing the session's own pull request. A draft (waiting for the founder) never lands.
- No force-push of a branch another pull request is built on, and no `git push --delete` of a branch someone else owns.

## Quick reference

```bash
gh pr list                                    # open pull requests (what is in flight)
git fetch origin && git switch -c feat/x origin/main
go tool -modfile=tools/pins/task/go.mod task check
git push -u origin HEAD && gh pr create --base main
tools/scripts/land.sh                         # check on top of main, then merge
```
