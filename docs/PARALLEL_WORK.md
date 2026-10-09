# Parallel work: several AI sessions on one repository

Read this before you start any task in this repository. It applies to every Claude Code session (desktop tab, terminal or IDE) and to people. It works together with the no-CI rule in [CLAUDE.md](../CLAUDE.md) ([EX-004](security/GATES_AND_REVIEW.md#4-exceptions)).

## Can two sessions work at the same time without breaking `main`?

Yes, if both follow this page. Two tasks can still conflict when they change the same lines, and no workflow prevents that. What this one does:

- each conflict shows up on one task branch, when that task lands, and is resolved there;
- `main` only moves forward (never force-pushed), and only to a commit that passed every local check *with all earlier landed work included*;
- two sessions landing at the same moment cannot overwrite each other: the second one notices, rebases and runs the checks again.

## Branches

| Branch | What it is | Rules |
|---|---|---|
| `main` | What is on GitHub. | Moves only through `tools/scripts/flow.sh land`. Never commit on it and never check it out. |
| `integration` | Local staging branch. Every worktree on this machine shares it. | Never check it out. Only `flow.sh` moves it, by compare-and-swap. After each landing it equals `origin/main`. |
| `task/<slug>` | One task. | One session per branch, in its own worktree. Private: rebasing it is fine. `land` deletes it. |

## The loop for every task

1. **Get a worktree of your own.** The desktop app gives each session one under `.claude/worktrees/`. Never work in another session's worktree. Two sessions in one folder overwrite each other's files.
2. **Look at what is in flight:** `tools/scripts/flow.sh status`. It lists every `task/*` branch and the files it changes. If your task needs the same files, say so to the founder before you start. Either wait for that task to land, or put your code in new files and keep your edits to the shared files to a few lines.
3. **Start:** `tools/scripts/flow.sh start <slug>` (for example `m4-215-pclaw`). It creates `task/<slug>` from the newest `integration`.
4. **Work in small steps.** A task should take about 30–60 minutes of agent time and stay under about 600 lines of non-generated diff ([BUILD_GUIDE](BUILD_GUIDE.md) §0). Split bigger work into several tasks and land them one after another. Commit often on your branch.
5. **Pick up other sessions' work** with `tools/scripts/flow.sh sync`, which rebases onto `integration`. Do it whenever someone lands, and at the latest before you land. Small, early syncs make conflicts small.
6. **Land:** `tools/scripts/flow.sh land`. It:
   1. rebases your branch onto `integration`;
   2. runs `task check`, `task test:integration` and `task trace` on the result (minutes, so run it in the background);
   3. moves `integration` to your commit, but only if nobody landed meanwhile; otherwise it rebases and checks again, up to 3 times;
   4. fast-forwards `origin/main` to the same commit, then deletes your task branch.

   A task is done only when `land` prints `landed`. If a check fails, fix it on your branch, commit and run `land` again. Never skip a check and never weaken a test to get through.
7. **Report** what landed (commit and summary) to the founder, then start the next task with `start`.

## Shared files: where conflicts come from

These files are touched by many tasks. Keep your edits to them small and prefer new files:

- server wiring: `internal/server/server.go`, `procedures.go`, `config.go` (add a `register…` function or a `wiring_<area>.go` file instead of growing `apiHandler`);
- the permission and role catalog: `internal/tenancy/domain/permissions.go`, `roles.go`;
- generated code: `internal/gen/**` (from `queries/*.sql`, `proto/**`, `sqlc.yaml`, `buf.gen.yaml`);
- `go.mod` / `go.sum`, `Taskfile.yml`;
- numbered things: `migrations/000NN_*.sql`, `HR-###` in [HARDENING_RULES](security/HARDENING_RULES.md), `T-###` in [THREAT_MODEL](security/THREAT_MODEL.md), proto field numbers;
- G0 briefs in `docs/g0/` and [FEATURES.md](FEATURES.md).

**Numbers.** Use the range the founder or the G0 brief gave your task. If there is none, take the next free number on `integration` when you start, and check it again after your last `sync`. A duplicate migration version makes `task test:integration` fail; renumber your file. A duplicate `HR`/`T` id must be renumbered in your branch, never in one that has landed.

## Resolving a conflict during `sync` or `land`

- **Generated code** (`internal/gen/**`): take either side, run `task gen` (it regenerates and fixes headers), and `git add` the result. Never hand-merge generated files.
- **`go.sum`**: take either side, then `go mod tidy`.
- **Everything else**: keep both sides' intent. Never drop another task's change to make yours fit. If you cannot tell what the other change needs, stop and ask the founder.
- Then `git add` the files, run `git rebase --continue`, and run `land` again. It checks everything once more.

## Shared resources

- **Test database:** all sessions share the cluster on `127.0.0.1:5433`. Each test creates its own database, so concurrent runs are safe. If it is down, `task up PROFILE=test`. Never stop, reset or wipe containers another session may be using.
- **Ports:** if you run a local server or gateway, use ports no other session uses.
- **Docker, the founder's credentials and GitHub settings** are shared. Change none of them unless the founder asks.

## What never happens

- No force-push, no `git push --delete`, no rewriting `main` or `integration`.
- No commits straight on `main` or `integration`. If `integration` and `origin/main` ever diverge, `flow.sh` stops: tell the founder.
- No pull requests and no CI while EX-004 lasts. The local checks in `land` are the only gate.

## Quick reference

```bash
tools/scripts/flow.sh status        # what is in flight, and which files each task changes
tools/scripts/flow.sh start <slug>  # new task branch from integration
tools/scripts/flow.sh sync          # pick up what others landed
tools/scripts/flow.sh land          # check everything, then land on integration and origin/main
```
