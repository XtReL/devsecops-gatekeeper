#!/usr/bin/env bash
# evidence-push_test.sh — integration test for evidence-push.sh against a
# real, local bare git repository, run in a git environment isolated from
# any ambient identity or config (no HOME, no global/system git config):
# the same shape of failure a bare GitHub Actions runner produces when
# evidence-push.sh forgets to set its own git identity.
#
# Exercises: the first record, a duplicate of the same run (must not add an
# entry), a second, different run, and a concurrent writer landing between
# our fetch and push (the optimistic retry must rebuild on top of it).
# Finishes with an end-to-end "trustcore verify" of the resulting log.
#
# Usage: evidence-push_test.sh <gatekeeper-bin> <trustcore-bin>
set -euo pipefail

GATEKEEPER_BIN_SRC=${1:?usage: evidence-push_test.sh <gatekeeper-bin> <trustcore-bin>}
TRUSTCORE_BIN=${2:?usage: evidence-push_test.sh <gatekeeper-bin> <trustcore-bin>}
PUSH_SCRIPT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/evidence-push.sh"

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

# Isolated git: no ambient identity or config of any kind, so a missing
# "git config user.name/user.email" in evidence-push.sh fails this test the
# same way it would fail on a bare runner.
export HOME="$WORK/home"
mkdir -p "$HOME"
export GIT_CONFIG_GLOBAL=/dev/null
export GIT_CONFIG_NOSYSTEM=1
unset GIT_AUTHOR_NAME GIT_AUTHOR_EMAIL GIT_COMMITTER_NAME GIT_COMMITTER_EMAIL || true

REPO="octo/evidence-selftest"
ORIGIN="$WORK/origin.git"
KEY="$WORK/signer.key"
PUB="$WORK/signer.pub"

git init --bare -q "$ORIGIN"
openssl genpkey -algorithm ed25519 -out "$KEY" 2>/dev/null
openssl pkey -in "$KEY" -pubout -out "$PUB" 2>/dev/null

# Bootstrap the orphan gatekeeper-evidence branch the way a client runs
# "gatekeeper evidence-init" once, locally (this step, and only this step,
# is allowed its own throwaway identity: it is not evidence-push.sh's job).
INIT_CLONE="$WORK/init-clone"
git clone -q "$ORIGIN" "$INIT_CLONE"
(cd "$INIT_CLONE" && git checkout --orphan gatekeeper-evidence -q && git rm -rf . -q >/dev/null 2>&1 || true)
"$GATEKEEPER_BIN_SRC" evidence-init --evidence "$INIT_CLONE" --repo "$REPO" --key "$KEY"
(
  cd "$INIT_CLONE"
  git -c user.name=init -c user.email=init@example.invalid add -A
  git -c user.name=init -c user.email=init@example.invalid commit -q -m init
  git push -q origin gatekeeper-evidence
)

EVIDENCE="$WORK/evidence"
git clone -q --branch gatekeeper-evidence --single-branch "$ORIGIN" "$EVIDENCE"

SCAN_SRC="$WORK/scan-src"
mkdir -p "$SCAN_SRC"
echo "nothing to see here" >"$SCAN_SRC/readme.txt"
RESULT="$WORK/result.json"
"$GATEKEEPER_BIN_SRC" scan --source "$SCAN_SRC" --out "$RESULT"

commit_a=$(printf 'a%.0s' $(seq 1 40))
commit_b=$(printf 'b%.0s' $(seq 1 40))
commit_c=$(printf 'c%.0s' $(seq 1 40))

run_push() {
  local evidence_dir="$1" commit="$2" run_id="$3"
  GATEKEEPER_SIGNING_KEY="$(cat "$KEY")" \
  GATEKEEPER_BIN="$GATEKEEPER_BIN_SRC" \
  RESULT_FILE="$RESULT" \
  EVIDENCE_DIR="$evidence_dir" \
  REPO="$REPO" \
  COMMIT="$commit" \
  RUN_URL="https://example.invalid/actions/runs/$run_id" \
  RUN_ID="$run_id" \
  RUN_ATTEMPT="1" \
  "$PUSH_SCRIPT"
}

entry_count() { git -C "$1" -c core.fileMode=false ls-files entries | grep -cv '\.gitkeep$' || true; }

echo "== evidence-push_test: first record =="
run_push "$EVIDENCE" "$commit_a" "1001"
[ "$(entry_count "$EVIDENCE")" -eq 1 ] || { echo "FAIL: expected 1 entry after the first record" >&2; exit 1; }

echo "== evidence-push_test: duplicate of the same run (no new entry) =="
before_head=$(git -C "$EVIDENCE" rev-parse HEAD)
run_push "$EVIDENCE" "$commit_a" "1001"
after_head=$(git -C "$EVIDENCE" rev-parse HEAD)
[ "$before_head" = "$after_head" ] || { echo "FAIL: duplicate run_id/run_attempt produced a new commit" >&2; exit 1; }
[ "$(entry_count "$EVIDENCE")" -eq 1 ] || { echo "FAIL: duplicate run_id/run_attempt added an entry" >&2; exit 1; }

echo "== evidence-push_test: second, different run =="
run_push "$EVIDENCE" "$commit_b" "1002"
[ "$(entry_count "$EVIDENCE")" -eq 2 ] || { echo "FAIL: expected 2 entries after the second run" >&2; exit 1; }

echo "== evidence-push_test: concurrent writer race =="
RIVAL="$WORK/rival"
git clone -q --branch gatekeeper-evidence --single-branch "$ORIGIN" "$RIVAL"
STALE="$WORK/stale"
cp -r "$EVIDENCE" "$STALE"
rm -rf "$STALE/.git/index.lock" 2>/dev/null || true

# The rival writes and pushes run 2001 first...
run_push "$RIVAL" "$commit_c" "2001"

# ...then our stale checkout (still at the pre-rival tip) races to record a
# different run: its first fetch/reset must pick up the rival's commit, and
# it must still succeed rather than conflict.
run_push "$STALE" "$(printf 'd%.0s' $(seq 1 40))" "2002"
[ "$(entry_count "$STALE")" -eq 4 ] || { echo "FAIL: expected 4 entries after the race, got $(entry_count "$STALE")" >&2; exit 1; }

echo "== evidence-push_test: verify =="
"$TRUSTCORE_BIN" verify -log "$STALE" -origin "github.com/$REPO/gatekeeper-evidence/v1" -log-pub "$PUB" -attester-pub "$PUB"

echo "evidence-push_test: OK"
