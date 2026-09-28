#!/usr/bin/env bash
# rotation_test.sh — self-test for key rotation into a new evidence epoch
# (docs/tasks/rotation.md; trust-core ADR 0002, "trust-core/docs/adr/0002-key-rotation.md").
# Isolated git, like evidence-push_test.sh: no ambient identity or config.
# Keys are generated in the test and never committed. trustcore is built by
# the caller from the version pinned in go.mod.
#
# Scenario:
#   1. epoch 1: evidence-init, two records via evidence-push.sh.
#   2. planned rotation to epoch 2 (both keys): a new orphan branch
#      gatekeeper-evidence-e2 is created in the bare repo; a record pushed
#      with the epoch-2 config lands there, and gatekeeper-evidence itself
#      does not move; "trustcore verify-chain" against a manifest of both
#      epochs succeeds.
#   3. unplanned rotation to epoch 2 (new key only, from a trusted
#      checkpoint kept outside the log): "trustcore verify-chain" fails
#      without the verifier's manifest accepting the new key id, and
#      succeeds once it does.
#
# Usage: rotation_test.sh <gatekeeper-bin> <trustcore-bin>
set -euo pipefail

GATEKEEPER_BIN=${1:?usage: rotation_test.sh <gatekeeper-bin> <trustcore-bin>}
TRUSTCORE_BIN=${2:?usage: rotation_test.sh <gatekeeper-bin> <trustcore-bin>}
PUSH_SCRIPT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/evidence-push.sh"

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

# Isolated git: no ambient identity or config of any kind (same reasoning as
# evidence-push_test.sh).
export HOME="$WORK/home"
mkdir -p "$HOME"
export GIT_CONFIG_GLOBAL=/dev/null
export GIT_CONFIG_NOSYSTEM=1
unset GIT_AUTHOR_NAME GIT_AUTHOR_EMAIL GIT_COMMITTER_NAME GIT_COMMITTER_EMAIL || true

REPO="octo/rotation-selftest"
BASE_ORIGIN="github.com/$REPO/gatekeeper-evidence/v1"

genkey() {
  # $1 = output path prefix; writes $1.key and $1.pub.
  openssl genpkey -algorithm ed25519 -out "$1.key" 2>/dev/null
  openssl pkey -in "$1.key" -pubout -out "$1.pub" 2>/dev/null
}

git_id() {
  git -C "$1" -c user.name=init -c user.email=init@example.invalid "${@:2}"
}

entry_count() { git -C "$1" -c core.fileMode=false ls-files entries | grep -cv '\.gitkeep$' || true; }

# config_dir writes a .gatekeeper/evidence.json with the given epoch and
# echoes the directory: "gatekeeper record" (invoked by evidence-push.sh)
# reads it relative to its own working directory, exactly as it would read
# the checked-out repo's config in CI.
config_dir() {
  local epoch="$1"
  local dir="$WORK/cfg-e$epoch"
  mkdir -p "$dir/.gatekeeper"
  printf '{"epoch": %d}\n' "$epoch" >"$dir/.gatekeeper/evidence.json"
  echo "$dir"
}

push_record() {
  local config_dir="$1" evidence_dir="$2" branch="$3" repo="$4" key="$5" commit="$6" run_id="$7"
  (
    cd "$config_dir"
    GATEKEEPER_SIGNING_KEY="$(cat "$key")" \
    GATEKEEPER_BIN="$GATEKEEPER_BIN" \
    RESULT_FILE="$RESULT" \
    EVIDENCE_DIR="$evidence_dir" \
    EVIDENCE_BRANCH="$branch" \
    REPO="$repo" \
    COMMIT="$commit" \
    RUN_URL="https://example.invalid/actions/runs/$run_id" \
    RUN_ID="$run_id" \
    RUN_ATTEMPT="1" \
    "$PUSH_SCRIPT"
  )
}

# ---------------------------------------------------------------------------
# 1. Epoch 1: init, two records through evidence-push.sh.
# ---------------------------------------------------------------------------

echo "== rotation_test: epoch 1 =="

ORIGIN="$WORK/origin.git"
git init --bare -q "$ORIGIN"

genkey "$WORK/e1"

INIT_CLONE="$WORK/init-clone"
git clone -q "$ORIGIN" "$INIT_CLONE"
(cd "$INIT_CLONE" && git checkout --orphan gatekeeper-evidence -q && git rm -rf . -q >/dev/null 2>&1 || true)
"$GATEKEEPER_BIN" evidence-init --evidence "$INIT_CLONE" --repo "$REPO" --key "$WORK/e1.key"
git_id "$INIT_CLONE" add -A
git_id "$INIT_CLONE" commit -q -m init
git -C "$INIT_CLONE" push -q origin gatekeeper-evidence

EVIDENCE_E1="$WORK/evidence-e1"
git clone -q --branch gatekeeper-evidence --single-branch "$ORIGIN" "$EVIDENCE_E1"

SCAN_SRC="$WORK/scan-src"
mkdir -p "$SCAN_SRC"
echo "nothing to see here" >"$SCAN_SRC/readme.txt"
RESULT="$WORK/result.json"
"$GATEKEEPER_BIN" scan --source "$SCAN_SRC" --out "$RESULT"

CFG_E1="$(config_dir 1)"
commit_a=$(printf 'a%.0s' $(seq 1 40))
commit_b=$(printf 'b%.0s' $(seq 1 40))
push_record "$CFG_E1" "$EVIDENCE_E1" "gatekeeper-evidence" "$REPO" "$WORK/e1.key" "$commit_a" "1001"
push_record "$CFG_E1" "$EVIDENCE_E1" "gatekeeper-evidence" "$REPO" "$WORK/e1.key" "$commit_b" "1002"

[ "$(entry_count "$EVIDENCE_E1")" -eq 2 ] || { echo "FAIL: expected 2 entries in epoch 1" >&2; exit 1; }

# An external, trusted copy of the epoch-1 checkpoint at this exact size —
# what an owner or auditor would have kept outside the log — for the
# unplanned rotation below (ADR 0002: the freeze point of an unplanned
# rotation is this trusted checkpoint, never the log's current file state).
TRUSTED_CP="$WORK/trusted-checkpoint-e1"
cp "$EVIDENCE_E1/checkpoint" "$TRUSTED_CP"

gatekeeper_evidence_before=$(git ls-remote "$ORIGIN" gatekeeper-evidence | cut -f1)

# ---------------------------------------------------------------------------
# 2. Planned rotation to epoch 2.
# ---------------------------------------------------------------------------

echo "== rotation_test: planned rotation to epoch 2 =="

genkey "$WORK/e2"
NEW_E2_DIR="$WORK/new-e2"
"$TRUSTCORE_BIN" rotate \
  -from "$EVIDENCE_E1" \
  -from-origin "$BASE_ORIGIN" \
  -from-pub "$WORK/e1.pub" \
  -from-key "$WORK/e1.key" \
  -new-key "$WORK/e2.key" \
  -to "$NEW_E2_DIR" \
  -note "scheduled rotation"

E2_CLONE="$WORK/e2-clone"
git clone -q "$ORIGIN" "$E2_CLONE"
(cd "$E2_CLONE" && git checkout --orphan gatekeeper-evidence-e2 -q && git rm -rf . -q >/dev/null 2>&1 || true)
cp -r "$NEW_E2_DIR"/. "$E2_CLONE"/
git_id "$E2_CLONE" add -A
git_id "$E2_CLONE" commit -q -m "rotate: epoch 2 genesis"
git -C "$E2_CLONE" push -q origin gatekeeper-evidence-e2

CFG_E2="$(config_dir 2)"
commit_c=$(printf 'c%.0s' $(seq 1 40))
push_record "$CFG_E2" "$E2_CLONE" "gatekeeper-evidence-e2" "$REPO" "$WORK/e2.key" "$commit_c" "2001"

[ "$(entry_count "$E2_CLONE")" -eq 2 ] || { echo "FAIL: expected 2 entries in epoch 2 (genesis + 1 record), got $(entry_count "$E2_CLONE")" >&2; exit 1; }

gatekeeper_evidence_after=$(git ls-remote "$ORIGIN" gatekeeper-evidence | cut -f1)
[ "$gatekeeper_evidence_before" = "$gatekeeper_evidence_after" ] || {
  echo "FAIL: gatekeeper-evidence moved during the epoch-2 rotation/push" >&2
  exit 1
}

MANIFEST_PLANNED="$WORK/manifest-planned.json"
cat >"$MANIFEST_PLANNED" <<EOF
{
  "base": "$BASE_ORIGIN",
  "epochs": [
    {"epoch": 1, "log": "$EVIDENCE_E1", "publicKey": "$WORK/e1.pub"},
    {"epoch": 2, "log": "$E2_CLONE", "publicKey": "$WORK/e2.pub"}
  ]
}
EOF
"$TRUSTCORE_BIN" verify-chain -manifest "$MANIFEST_PLANNED"

# ---------------------------------------------------------------------------
# 3. Unplanned rotation to epoch 2, from the same epoch-1 state.
# ---------------------------------------------------------------------------

echo "== rotation_test: unplanned rotation to epoch 2 =="

genkey "$WORK/e2u"
NEW_E2U_DIR="$WORK/new-e2-unplanned"
rotate_out=$("$TRUSTCORE_BIN" rotate \
  -from "$EVIDENCE_E1" \
  -from-origin "$BASE_ORIGIN" \
  -from-pub "$WORK/e1.pub" \
  -trusted-checkpoint "$TRUSTED_CP" \
  -new-key "$WORK/e2u.key" \
  -to "$NEW_E2U_DIR" \
  -note "old key lost")
echo "$rotate_out"
new_keyid=$(printf '%s\n' "$rotate_out" | sed -n 's/^key id:[[:space:]]*//p')
[ -n "$new_keyid" ] || { echo "FAIL: could not read the new key id from 'trustcore rotate' output" >&2; exit 1; }

MANIFEST_NO_ACCEPT="$WORK/manifest-unplanned-no-accept.json"
cat >"$MANIFEST_NO_ACCEPT" <<EOF
{
  "base": "$BASE_ORIGIN",
  "epochs": [
    {"epoch": 1, "log": "$EVIDENCE_E1", "publicKey": "$WORK/e1.pub"},
    {"epoch": 2, "log": "$NEW_E2U_DIR", "publicKey": "$WORK/e2u.pub"}
  ]
}
EOF

set +e
"$TRUSTCORE_BIN" verify-chain -manifest "$MANIFEST_NO_ACCEPT" >/dev/null 2>&1
no_accept_code=$?
set -e
[ "$no_accept_code" -eq 1 ] || {
  echo "FAIL: verify-chain without acceptUnplanned: expected exit code 1, got $no_accept_code" >&2
  exit 1
}

MANIFEST_ACCEPT="$WORK/manifest-unplanned-accept.json"
cat >"$MANIFEST_ACCEPT" <<EOF
{
  "base": "$BASE_ORIGIN",
  "epochs": [
    {"epoch": 1, "log": "$EVIDENCE_E1", "publicKey": "$WORK/e1.pub"},
    {"epoch": 2, "log": "$NEW_E2U_DIR", "publicKey": "$WORK/e2u.pub", "acceptUnplanned": "$new_keyid"}
  ]
}
EOF

set +e
"$TRUSTCORE_BIN" verify-chain -manifest "$MANIFEST_ACCEPT" >/dev/null 2>&1
accept_code=$?
set -e
[ "$accept_code" -eq 0 ] || {
  echo "FAIL: verify-chain with the correct acceptUnplanned key id: expected exit code 0, got $accept_code" >&2
  exit 1
}

echo "rotation_test: OK"
