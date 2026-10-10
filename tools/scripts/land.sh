#!/usr/bin/env bash
# SPDX-License-Identifier: BUSL-1.1
# Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
#
# Lands pull requests on main, one at a time, through one queue shared by
# every worktree of this repository (docs/PARALLEL_WORK.md, founder decision
# 2026-10-10). Run it from Git Bash on Windows or any POSIX shell.
#
#   tools/scripts/land.sh             queue this branch's pull request and wait
#                                     for the lander's result (task land)
#   tools/scripts/land.sh --no-wait   queue it and return
#   tools/scripts/land.sh --pr <n>    queue pull request n from any worktree, for
#                                     one whose session stopped (with --no-wait
#                                     to return at once)
#   tools/scripts/land.sh --status    show the queue, the lander and recent results
#   tools/scripts/land.sh --serve     be the lander: land queued pull requests in
#                                     order, one at a time (task land:serve)
#   tools/scripts/land.sh --serve --once   the same, until the queue is empty
#
# Queueing refuses a draft (a draft waits for the founder), a base other than
# main (land that base first) and uncommitted changes, pushes the branch, and
# adds the pull request at the end of the queue. Only one lander runs, in a
# clean worktree of its own; it takes the oldest entry and:
#   1. checks out the pull request's head and merges origin/main into it (a
#      conflict fails the entry: the owner merges main, resolves, pushes and
#      queues again);
#   2. runs task check, task test:integration (unless only docs changed) and
#      task trace on that result; a failure, or a check that cannot run,
#      fails the entry;
#   3. pushes the checked commit to the pull request's branch and, if main has
#      not moved meanwhile, squash-merges the pull request pinned to exactly
#      that commit; if main moved, it starts again from 1;
#   4. writes the result, comments on the pull request, and takes the next
#      entry.
# Landings never run side by side, so they never compete for the test
# cluster or merge on top of each other. The lander waits while the test
# cluster is down instead of failing every entry, and restarts itself when a
# landing changes this script on main. It never force-pushes, never pushes to
# main and never merges a commit the checks did not pass on top of the main
# it merges into.
set -euo pipefail

TASK="go tool -modfile=tools/pins/task/go.mod task"
MAX_ATTEMPTS=3
POLL=10   # seconds between queue and result checks
STALE=120 # seconds without a lander heartbeat (touched every 15 s) before it counts as gone

die() { echo "land: $*" >&2; exit 1; }
say() { echo "land: $*"; }
usage() {
  awk 'NR >= 5 && /^#/ { sub(/^# ?/, ""); print; next } NR >= 5 { exit }' "$0"
  exit 2
}

MODE=queue
WAIT=1
ONCE=0
PR=""
while [ $# -gt 0 ]; do
  case "$1" in
    --no-wait) WAIT=0 ;;
    --status) MODE=status ;;
    --serve) MODE=serve ;;
    --once) ONCE=1 ;;
    --pr)
      PR="${2:-}"
      [[ "$PR" =~ ^[0-9]+$ ]] || usage
      shift
      ;;
    *) usage ;;
  esac
  shift
done

cd "$(git rev-parse --show-toplevel)"
command -v gh >/dev/null 2>&1 || die "the GitHub CLI (gh) is required"
STATE="$(git rev-parse --path-format=absolute --git-common-dir)/pantherclaw-land"
QUEUE="$STATE/queue"
RESULTS="$STATE/results"
LOGS="$STATE/logs"
LOCK="$STATE/lander.lock"
BEAT="$STATE/lander.heartbeat"
mkdir -p "$QUEUE" "$RESULTS" "$LOGS"

# age prints how many seconds ago a file changed (a large number when it
# does not exist).
age() {
  if [ -e "$1" ]; then
    echo $(($(date +%s) - $(date -r "$1" +%s)))
  else
    echo 999999
  fi
}

lander_alive() { [ -d "$LOCK" ] && [ "$(age "$BEAT")" -lt "$STALE" ]; }

# cluster_up reports whether the test cluster answers on 127.0.0.1:5433.
cluster_up() { (exec 3<>/dev/tcp/127.0.0.1/5433) 2>/dev/null; }

# field reads one key=value line of a queue entry.
field() { sed -n "s/^$2=//p" "$1" | head -1; }

# entries lists the queue, oldest first.
entries() { find "$QUEUE" -maxdepth 1 -type f ! -name '.*' | sort; }

status() {
  if lander_alive; then
    echo "lander: running in $(field "$LOCK/owner" worktree 2>/dev/null || echo '?') (heartbeat $(age "$BEAT")s ago)"
    if [ -f "$STATE/current" ]; then
      echo "landing now: #$(field "$STATE/current" pr) ($(field "$STATE/current" branch)) since $(field "$STATE/current" started)"
    fi
  else
    echo "lander: NOT RUNNING. Start it in the lander session: task land:serve"
  fi
  cluster_up || echo "test cluster: DOWN on 127.0.0.1:5433 (task up PROFILE=test); the lander waits for it"
  local n=0 e
  while IFS= read -r e; do
    [ -n "$e" ] || continue
    n=$((n + 1))
    echo "queued $n: #$(field "$e" pr) ($(field "$e" branch)) since $(field "$e" queued)"
  done < <(entries)
  [ "$n" -gt 0 ] || echo "queue: empty"
  echo "recent results:"
  # shellcheck disable=SC2012 # names are ours: no spaces
  ls -t "$RESULTS" 2>/dev/null | head -5 | while read -r r; do echo "  $r: $(head -1 "$RESULTS/$r")"; done
}

# docs_only reports whether HEAD changes documentation only beyond origin/main.
docs_only() {
  local f
  while IFS= read -r f; do
    case "$f" in
      docs/* | *.md) ;;
      *) return 1 ;;
    esac
  done < <(git diff --name-only origin/main HEAD)
}

# ---------------------------------------------------------------- queueing --

queue() {
  local branch number state draft base head entry id info
  if [ -n "$PR" ]; then
    info="$(gh pr view "$PR" --json number,state,isDraft,baseRefName,headRefName,headRefOid \
      --jq '"\(.number) \(.state) \(.isDraft) \(.baseRefName) \(.headRefName) \(.headRefOid)"' 2>/dev/null)" ||
      die "cannot read pull request #$PR"
    read -r number state draft base branch head <<<"$info"
  else
    branch="$(git symbolic-ref --quiet --short HEAD)" || die "HEAD is detached; switch to the task's branch"
    [ "$branch" != main ] || die "you are on main; land from the task's branch"
    [ -z "$(git status --porcelain)" ] || die "the worktree has uncommitted changes; commit them first"
    info="$(gh pr view "$branch" --json number,state,isDraft,baseRefName \
      --jq '"\(.number) \(.state) \(.isDraft) \(.baseRefName)"' 2>/dev/null)" ||
      die "no pull request for $branch; open one first (gh pr create --base main)"
    read -r number state draft base <<<"$info"
  fi
  [ "$state" = OPEN ] || die "pull request #$number is $state"
  [ "$draft" = false ] || die "pull request #$number is a draft: it waits for the founder. Once they agree, run: gh pr ready $number"
  [ "$base" = main ] || die "pull request #$number is based on $base: land that one first; GitHub then moves this one onto main"

  if [ -z "$PR" ]; then
    # A failed landing may have pushed the lander's merge of main: take it,
    # then publish this branch.
    git fetch --quiet origin "$branch" 2>/dev/null || true
    if git rev-parse --verify --quiet "origin/$branch" >/dev/null && ! git merge-base --is-ancestor "origin/$branch" HEAD; then
      say "taking the commits already on origin/$branch"
      git merge --quiet --no-edit "origin/$branch" || die "merging origin/$branch stopped on a conflict; resolve it, commit, and run land again"
    fi
    git push --quiet origin "HEAD:refs/heads/$branch" || die "pushing $branch was refused; look at the branch, then run land again"
    head="$(git rev-parse HEAD)"
  fi

  while IFS= read -r entry; do
    if [ -n "$entry" ] && [ "$(field "$entry" pr)" = "$number" ]; then
      id="$(basename "$entry")"
      say "#$number is already queued"
      [ "$WAIT" = 1 ] && wait_for "$id" "$number"
      return 0
    fi
  done < <(entries)
  id="$(date +%s%N)-$number"
  {
    echo "pr=$number"
    echo "branch=$branch"
    echo "head=$head"
    echo "worktree=$([ -n "$PR" ] && echo "-" || pwd)"
    echo "queued=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  } >"$QUEUE/.$id.tmp"
  mv "$QUEUE/.$id.tmp" "$QUEUE/$id"
  say "queued #$number ($branch) at position $(entries | wc -l | tr -d ' ')"
  lander_alive || say "WARNING: no lander is running; the lander session starts it with: task land:serve"
  if [ "$WAIT" = 0 ]; then
    say "not waiting; see the result with: tools/scripts/land.sh --status"
    return 0
  fi
  wait_for "$id" "$number"
}

# wait_for waits for the lander's result of entry id, prints it, and exits
# with it: 0 when landed.
wait_for() {
  local id="$1" number="$2" result="$RESULTS/$1" last="" now pos warned=0
  while [ ! -f "$result" ]; do
    if grep -q "^pr=$number\$" "$STATE/current" 2>/dev/null; then
      now="being landed"
    elif [ -f "$QUEUE/$id" ]; then
      pos="$(entries | grep -n "/$id\$" | cut -d: -f1)"
      now="queued at position $pos"
    else
      sleep 2
      [ -f "$result" ] && break
      die "#$number left the queue without a result (removed by hand?); see tools/scripts/land.sh --status"
    fi
    if [ "$now" != "$last" ]; then
      say "#$number: $now"
      last="$now"
    fi
    if [ "$warned" = 0 ] && ! lander_alive; then
      say "WARNING: no lander is running; #$number waits until one starts (task land:serve)"
      warned=1
    fi
    sleep "$POLL"
  done
  cat "$result"
  head -1 "$result" | grep -q '^landed' || exit 1
}

# ----------------------------------------------------------------- landing --

# clean_worktree drops whatever the previous landing left in the lander's
# own worktree (a stopped merge, files a check wrote). Ignored files, such as
# deploy/compose/.env, stay.
clean_worktree() {
  git merge --abort 2>/dev/null || true
  git reset --quiet --hard 2>/dev/null || true
  git clean --quiet -fd 2>/dev/null || true
}

serve() {
  [ -z "$(git status --porcelain)" ] || die "the lander's worktree has uncommitted changes; it lands from a clean worktree of its own"
  [ -f deploy/compose/.env ] || die "the lander's worktree has no deploy/compose/.env, which task test:integration needs"
  git fetch --quiet origin main || true
  if git merge-base --is-ancestor HEAD origin/main &&
    [ "$(git rev-parse HEAD:tools/scripts/land.sh)" != "$(git rev-parse origin/main:tools/scripts/land.sh)" ]; then
    say "main has a newer land.sh than this worktree; starting that one"
    git switch --quiet --detach origin/main
    [ "$ONCE" = 1 ] && exec bash tools/scripts/land.sh --serve --once
    exec bash tools/scripts/land.sh --serve
  fi
  if ! mkdir "$LOCK" 2>/dev/null; then
    lander_alive && die "a lander is already running in $(field "$LOCK/owner" worktree 2>/dev/null || echo '?'); see tools/scripts/land.sh --status"
    say "taking over from a lander that stopped $(age "$BEAT")s ago"
    rm -rf "$LOCK"
    mkdir "$LOCK" || die "could not take the lander lock"
  fi
  printf 'worktree=%s\npid=%s\nstarted=%s\n' "$(pwd)" "$$" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" >"$LOCK/owner"
  touch "$BEAT"
  (while kill -0 $$ 2>/dev/null; do touch "$BEAT"; sleep 15; done) &
  BEAT_PID=$!
  trap 'kill "$BEAT_PID" 2>/dev/null; rm -rf "$LOCK" "$STATE/current"' EXIT
  say "lander running in $(pwd); queue in $QUEUE"
  # seen is this script as main had it when the lander started: a landing
  # that changes it there restarts the lander with the new version.
  local entry seen waiting=0
  seen="$(git rev-parse origin/main:tools/scripts/land.sh)"
  while true; do
    entry="$(entries | head -1)"
    if [ -z "$entry" ]; then
      [ "$ONCE" = 1 ] && { say "queue empty; stopping (--once)"; return 0; }
      sleep "$POLL"
      continue
    fi
    if ! cluster_up; then
      [ "$waiting" = 1 ] || say "the test cluster on 127.0.0.1:5433 is down; waiting for it (task up PROFILE=test)"
      waiting=1
      sleep "$POLL"
      continue
    fi
    waiting=0
    git fetch --quiet origin main || true
    if [ "$(git rev-parse origin/main:tools/scripts/land.sh)" != "$seen" ]; then
      say "land.sh changed on main; restarting the lander with the new version"
      clean_worktree
      git switch --quiet --detach origin/main
      kill "$BEAT_PID" 2>/dev/null || true
      rm -rf "$LOCK"
      trap - EXIT
      if [ "$ONCE" = 1 ]; then
        exec bash tools/scripts/land.sh --serve --once
      fi
      exec bash tools/scripts/land.sh --serve
    fi
    land_entry "$entry" || true
  done
}

# land_entry lands one queue entry and records the result; it never exits
# the lander.
land_entry() {
  local entry="$1" id number branch log result rc
  id="$(basename "$entry")"
  number="$(field "$entry" pr)"
  branch="$(field "$entry" branch)"
  log="$LOGS/$id.log"
  result="$RESULTS/$id"
  { cat "$entry"; echo "started=$(date -u +%Y-%m-%dT%H:%M:%SZ)"; } >"$STATE/current"
  say "landing #$number ($branch); log $log"
  clean_worktree
  set +e
  (set -e; land_pr "$number" "$branch") >"$log" 2>&1
  rc=$?
  set -e
  if [ "$rc" = 0 ]; then
    grep '^land: landed' "$log" | tail -1 | sed 's/^land: //' >"$result"
  else
    { echo "failed: $(grep '^land: ' "$log" | tail -1 | sed 's/^land: //')"; echo "log: $log"; tail -40 "$log"; } >"$result"
  fi
  gh pr comment "$number" --body "$(printf 'Lander: %s\n\n<details><summary>log tail</summary>\n\n```\n%s\n```\n</details>' \
    "$(head -1 "$result")" "$(tail -25 "$log")")" >/dev/null 2>&1 || true
  rm -f "$entry" "$STATE/current"
  clean_worktree
  git switch --quiet --detach origin/main 2>/dev/null || true
  say "#$number: $(head -1 "$result")"
}

gate() {
  say "task check"
  $TASK check || die "task check failed; fix it, push, and queue again (task land)"
  if docs_only; then
    say "only docs changed: no task test:integration"
  else
    say "task test:integration (test cluster on 127.0.0.1:5433: task up PROFILE=test; needs deploy/compose/.env)"
    $TASK test:integration || die "task test:integration failed or could not run; fix it, push, and queue again (task land)"
  fi
  say "task trace"
  $TASK trace || die "task trace failed; fix it, push, and queue again (task land)"
}

# land_pr runs in a subshell: die ends the landing, not the lander.
land_pr() {
  local number="$1" branch="$2" info state draft base head tested_main merged parent
  info="$(gh pr view "$number" --json state,isDraft,baseRefName --jq '"\(.state) \(.isDraft) \(.baseRefName)"')" ||
    die "cannot read pull request #$number"
  read -r state draft base <<<"$info"
  if [ "$state" = MERGED ]; then
    # A lander stopped between the merge and the result: report it.
    merged="$(gh pr view "$number" --json mergeCommit --jq .mergeCommit.oid || true)"
    say "landed #$number on main as $(printf '%.7s' "$merged") (merged earlier)"
    return 0
  fi
  [ "$state" = OPEN ] || die "pull request #$number is $state"
  [ "$draft" = false ] || die "pull request #$number became a draft"
  [ "$base" = main ] || die "pull request #$number is based on $base"
  git fetch --quiet origin main "$branch" || die "cannot fetch $branch"
  git switch --quiet --detach "origin/$branch" || die "cannot check out $branch"
  for attempt in $(seq 1 "$MAX_ATTEMPTS"); do
    git fetch --quiet origin main
    if ! git merge-base --is-ancestor origin/main HEAD; then
      say "merging origin/main $(git rev-parse --short origin/main) into $branch"
      if ! git merge --quiet --no-edit -m "Merge remote-tracking branch 'origin/main' into $branch" origin/main; then
        git merge --abort 2>/dev/null || true
        die "merging main into $branch stopped on a conflict. The owner merges origin/main, resolves it (task gen for internal/gen, go mod tidy for go.sum, keep both sides' intent elsewhere), pushes, and queues again"
      fi
    fi
    git diff --quiet origin/main HEAD && die "nothing to land: $branch has no changes beyond main"
    head="$(git rev-parse HEAD)"
    tested_main="$(git rev-parse origin/main)"
    say "attempt $attempt: checking $(git rev-parse --short "$head") on main $(git rev-parse --short "$tested_main")"
    gate
    git push --quiet origin "HEAD:refs/heads/$branch" ||
      die "the push to $branch was refused: its owner pushed meanwhile. They queue it again (task land)"
    git fetch --quiet origin main
    if [ "$(git rev-parse origin/main)" != "$tested_main" ]; then
      say "main moved while the checks ran; merging it and checking again"
      continue
    fi
    gh pr merge "$number" --squash --match-head-commit "$head" || die "GitHub refused to merge #$number; see the pull request"
    merged="$(gh pr view "$number" --json mergeCommit --jq .mergeCommit.oid || true)"
    say "landed #$number on main as $(printf '%.7s' "$merged")"
    parent="$(gh api "repos/{owner}/{repo}/commits/$merged" --jq '.parents[0].sha' 2>/dev/null || true)"
    if [ -n "$parent" ] && [ "$parent" != "$tested_main" ]; then
      say "WARNING: main moved during the merge (outside the queue?); check the new main"
    fi
    return 0
  done
  die "main kept moving while the checks ran; queue #$number again"
}

# One brace group: bash reads all of it before running it, so a landing that
# checks out another version of this file cannot change the running script.
{
  case "$MODE" in
    status) status ;;
    serve) serve ;;
    queue) queue ;;
  esac
  exit 0
}
