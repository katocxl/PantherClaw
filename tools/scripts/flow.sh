#!/usr/bin/env bash
# SPDX-License-Identifier: BUSL-1.1
# Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
#
# Parallel work on one machine (docs/PARALLEL_WORK.md). Every session works
# on its own task branch in its own worktree, starts from the local
# `integration` branch and lands one task at a time:
#
#   tools/scripts/flow.sh start <slug>   new branch task/<slug> from integration
#   tools/scripts/flow.sh status         task branches in flight and the files they touch
#   tools/scripts/flow.sh sync           rebase the current task branch onto integration
#   tools/scripts/flow.sh land           sync, run every local check, then move
#                                        integration and origin/main to this commit
#
# Run it from Git Bash (Windows) or any POSIX shell, inside the worktree of
# the task. It never force-pushes and never checks out integration or main.
set -euo pipefail

TASK="go tool -modfile=tools/pins/task/go.mod task"
INTEGRATION=refs/heads/integration
MAX_LAND_ATTEMPTS=3

die() { echo "flow: $*" >&2; exit 1; }
say() { echo "flow: $*"; }

cd "$(git rev-parse --show-toplevel)"

current_branch() { git symbolic-ref --quiet --short HEAD || true; }

require_clean() {
  [ -z "$(git status --porcelain)" ] || die "the worktree has uncommitted changes; commit or stash them first"
}

require_task_branch() {
  local b
  b="$(current_branch)"
  case "$b" in
    task/*) ;;
    "") die "HEAD is detached; run: tools/scripts/flow.sh start <slug>" ;;
    *) die "branch $b is not a task branch; tasks live on task/<slug> (run: tools/scripts/flow.sh start <slug>)" ;;
  esac
}

# checked_out reports whether a branch is checked out in any worktree;
# integration and main never are, so their refs can move safely.
checked_out() { git worktree list --porcelain | grep -qx "branch refs/heads/$1"; }

# sync_integration fast-forwards integration to origin/main, creating it if
# needed. origin/main only moves through `land`, so the two never diverge;
# if they do, a person must look.
sync_integration() {
  git fetch --quiet origin main
  local remote local_ref
  remote="$(git rev-parse origin/main)"
  if ! local_ref="$(git rev-parse --verify --quiet "$INTEGRATION")"; then
    git update-ref "$INTEGRATION" "$remote" ""
    say "created integration at $(git rev-parse --short "$remote")"
    return
  fi
  if [ "$local_ref" = "$remote" ] || git merge-base --is-ancestor "$remote" "$local_ref"; then
    return
  fi
  if git merge-base --is-ancestor "$local_ref" "$remote"; then
    git update-ref "$INTEGRATION" "$remote" "$local_ref"
    say "integration fast-forwarded to origin/main $(git rev-parse --short "$remote")"
    return
  fi
  die "integration ($(git rev-parse --short "$local_ref")) and origin/main ($(git rev-parse --short "$remote")) have diverged; stop and ask the founder"
}

cmd_start() {
  local slug="${1:-}"
  [[ "$slug" =~ ^[a-z0-9][a-z0-9-]{1,48}$ ]] || die "usage: flow.sh start <slug> (lowercase letters, digits and dashes)"
  require_clean
  checked_out integration && die "integration is checked out in a worktree; switch that worktree to a task branch"
  sync_integration
  git rev-parse --verify --quiet "refs/heads/task/$slug" >/dev/null && die "task/$slug already exists (another session may own it)"
  git switch --quiet -c "task/$slug" integration
  git branch --quiet --unset-upstream 2>/dev/null || true
  say "on task/$slug from integration $(git rev-parse --short integration)"
  cmd_status
}

cmd_status() {
  local base b ahead
  base="$(git rev-parse --verify --quiet "$INTEGRATION")" || die "no integration branch yet; run: tools/scripts/flow.sh start <slug>"
  say "integration $(git rev-parse --short "$base"); task branches in flight:"
  while IFS= read -r b; do
    [ -n "$b" ] || continue
    ahead="$(git rev-list --count "$base..$b")"
    [ "$ahead" -gt 0 ] || { echo "  $b (nothing to land)"; continue; }
    echo "  $b: $ahead commit(s), behind integration by $(git rev-list --count "$b..$base")"
    git diff --name-only "$(git merge-base "$base" "$b")" "$b" | sed 's/^/      /'
  done < <(git for-each-ref --format='%(refname:short)' 'refs/heads/task/*')
}

cmd_sync() {
  require_task_branch
  require_clean
  sync_integration
  if git merge-base --is-ancestor "$INTEGRATION" HEAD; then
    say "already on top of integration"
    return
  fi
  if ! git rebase --quiet integration; then
    die "rebase stopped on a conflict. Resolve it (regenerate internal/gen with 'task gen' instead of editing it), 'git add' the files, 'git rebase --continue', then run land again"
  fi
  say "rebased onto integration $(git rev-parse --short integration)"
}

gate() {
  say "task check"
  $TASK check
  say "task test:integration (cluster on 127.0.0.1:5433; start it with: task up PROFILE=test)"
  $TASK test:integration
  say "task trace"
  $TASK trace
}

cmd_land() {
  require_task_branch
  require_clean
  checked_out integration && die "integration is checked out in a worktree; it must not be"
  local attempt base head
  for attempt in $(seq 1 "$MAX_LAND_ATTEMPTS"); do
    cmd_sync
    base="$(git rev-parse "$INTEGRATION")"
    head="$(git rev-parse HEAD)"
    [ "$base" != "$head" ] || die "nothing to land: the branch has no commits beyond integration"
    say "attempt $attempt: checking $(git rev-parse --short HEAD) on top of integration $(git rev-parse --short "$base")"
    gate
    # Compare-and-swap: integration moves only if nobody landed meanwhile.
    if git update-ref "$INTEGRATION" "$head" "$base" 2>/dev/null; then
      if ! git push origin "$head:refs/heads/main"; then
        git update-ref "$INTEGRATION" "$base" "$head"
        die "origin/main refused the fast-forward (someone pushed outside this flow); integration was put back. Run land again"
      fi
      say "landed $(git rev-parse --short "$head") on integration and origin/main"
      local done_branch
      done_branch="$(current_branch)"
      git switch --quiet --detach
      git branch --quiet -D "$done_branch"
      say "removed $done_branch; this worktree is now detached at the landed commit (start the next task with: flow.sh start <slug>)"
      return
    fi
    say "integration moved while the checks ran; rebasing and checking again"
  done
  die "integration kept moving; land again later"
}

case "${1:-}" in
  start) shift; cmd_start "$@" ;;
  status) cmd_status ;;
  sync) cmd_sync ;;
  land) cmd_land ;;
  *) sed -n '5,15p' "$0"; exit 2 ;;
esac
