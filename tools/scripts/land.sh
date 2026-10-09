#!/usr/bin/env bash
# SPDX-License-Identifier: BUSL-1.1
# Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
#
# Lands the current branch's pull request on main: the last step of every
# task (docs/PARALLEL_WORK.md, founder decision 2026-10-10). Run it inside
# the task's worktree, from Git Bash on Windows or any POSIX shell:
#
#   tools/scripts/land.sh            land this branch's pull request
#   tools/scripts/land.sh --dry-run  the same checks, without pushing or merging
#
# It refuses a draft pull request (a draft waits for the founder), one whose
# base is not main (land that base first), and uncommitted changes. Then:
#   1. it merges origin/main into the branch when the branch lacks it (a
#      conflict stops it: resolve, commit, run it again);
#   2. it runs task check, task test:integration (unless only docs changed)
#      and task trace on that result; a failure, or a check that cannot run,
#      stops it;
#   3. it pushes the checked commit and, if main has not moved meanwhile,
#      squash-merges the pull request pinned to exactly that commit; if main
#      moved, it starts again from 1.
# It never force-pushes, never pushes to main and never merges a commit the
# checks did not pass on top of the main it merges into.
set -euo pipefail

TASK="go tool -modfile=tools/pins/task/go.mod task"
MAX_ATTEMPTS=3
DRY=0

die() { echo "land: $*" >&2; exit 1; }
say() { echo "land: $*"; }

for arg in "$@"; do
  case "$arg" in
    --dry-run) DRY=1 ;;
    *) sed -n '5,23p' "$0"; exit 2 ;;
  esac
done

cd "$(git rev-parse --show-toplevel)"
command -v gh >/dev/null 2>&1 || die "the GitHub CLI (gh) is required"
branch="$(git symbolic-ref --quiet --short HEAD)" || die "HEAD is detached; switch to the task's branch"
[ "$branch" != main ] || die "you are on main; land from the task's branch"
[ -z "$(git status --porcelain)" ] || die "the worktree has uncommitted changes; commit them first"

pr="$(gh pr view "$branch" --json number,state,isDraft,baseRefName --jq '"\(.number) \(.state) \(.isDraft) \(.baseRefName)"' 2>/dev/null)" ||
  die "no pull request for $branch; open one first (gh pr create --base main)"
read -r number state draft base <<<"$pr"
[ "$state" = OPEN ] || die "pull request #$number is $state"
[ "$draft" = false ] || die "pull request #$number is a draft: it waits for the founder. Once they agree, run: gh pr ready $number"
[ "$base" = main ] || die "pull request #$number is based on $base: land that one first; GitHub then moves this one onto main"

# docs_only reports whether the change touches documentation only, which
# needs no integration run.
docs_only() {
  local f
  while IFS= read -r f; do
    case "$f" in
      docs/* | *.md) ;;
      *) return 1 ;;
    esac
  done < <(git diff --name-only origin/main HEAD)
}

gate() {
  say "task check"
  $TASK check || die "task check failed; fix it, commit, and run land again"
  if docs_only; then
    say "only docs changed: no task test:integration"
  else
    say "task test:integration (test cluster on 127.0.0.1:5433: task up PROFILE=test; needs deploy/compose/.env)"
    $TASK test:integration || die "task test:integration failed or could not run; fix it, commit, and run land again"
  fi
  say "task trace"
  $TASK trace || die "task trace failed; fix it, commit, and run land again"
}

for attempt in $(seq 1 "$MAX_ATTEMPTS"); do
  git fetch --quiet origin main
  if ! git merge-base --is-ancestor origin/main HEAD; then
    say "merging origin/main $(git rev-parse --short origin/main) into $branch"
    git merge --quiet --no-edit origin/main ||
      die "the merge stopped on a conflict. Resolve it (task gen for internal/gen, go mod tidy for go.sum, keep both sides' intent everywhere else), commit, and run land again"
  fi
  git diff --quiet origin/main HEAD && die "nothing to land: the branch has no changes beyond main"
  head="$(git rev-parse HEAD)"
  tested_main="$(git rev-parse origin/main)"
  say "attempt $attempt: checking $(git rev-parse --short "$head") on main $(git rev-parse --short "$tested_main")"
  gate
  if [ "$DRY" = 1 ]; then
    say "dry run: every check passed on $(git rev-parse --short "$head"); nothing pushed or merged"
    exit 0
  fi
  git push --quiet origin "HEAD:refs/heads/$branch" ||
    die "the push was refused (did someone else push to $branch?); look at the branch, then run land again"
  git fetch --quiet origin main
  if [ "$(git rev-parse origin/main)" != "$tested_main" ]; then
    say "main moved while the checks ran; merging it and checking again"
    continue
  fi
  gh pr merge "$number" --squash --match-head-commit "$head" ||
    die "GitHub refused to merge #$number; see the pull request"
  merged="$(gh pr view "$number" --json mergeCommit --jq .mergeCommit.oid)"
  say "landed #$number on main as $(printf '%.7s' "$merged")"
  # Another landing in the second between the last fetch and the merge
  # would put this squash on a main the checks did not see.
  parent="$(gh api "repos/{owner}/{repo}/commits/$merged" --jq '.parents[0].sha' 2>/dev/null || true)"
  if [ -n "$parent" ] && [ "$parent" != "$tested_main" ]; then
    say "WARNING: main moved during the merge; run task check and task test:integration on the new main and fix anything that broke"
  fi
  say "start the next task from the new main: git fetch origin && git switch -c <type>/<slug> origin/main"
  exit 0
done
die "main kept moving while the checks ran; run land again"
