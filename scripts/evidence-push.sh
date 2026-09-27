#!/usr/bin/env bash
# evidence-push.sh — optimistic, retried append to the gatekeeper-evidence
# branch. See docs/adr/0001-action-evidence.md, decision A and amendments
# 2 and 3: no concurrency group (GitHub cancels a queued run when another
# lands, which would silently drop the middle push of a fast burst), and no
# git rebase (the checkpoint file changes on every record, so a rebase would
# conflict on it every single time). Instead: fetch, hard reset to the
# remote branch, record again, push — up to 5 attempts with a growing,
# jittered delay.
#
# Required environment:
#   GATEKEEPER_BIN, RESULT_FILE, EVIDENCE_DIR, REPO, COMMIT, RUN_URL,
#   RUN_ID, RUN_ATTEMPT, GATEKEEPER_SIGNING_KEY (read by "gatekeeper record"
#   itself; this script never touches it).
set -uo pipefail

: "${GATEKEEPER_BIN:?GATEKEEPER_BIN is required}"
: "${RESULT_FILE:?RESULT_FILE is required}"
: "${EVIDENCE_DIR:?EVIDENCE_DIR is required}"
: "${REPO:?REPO is required}"
: "${COMMIT:?COMMIT is required}"
: "${RUN_URL:?RUN_URL is required}"
: "${RUN_ID:?RUN_ID is required}"
: "${RUN_ATTEMPT:?RUN_ATTEMPT is required}"

# A GitHub Actions runner has no global git identity, so a bare `git commit`
# in $EVIDENCE_DIR fails with "Author identity unknown". Set one here, once,
# rather than relying on ambient config that may not exist.
git -C "$EVIDENCE_DIR" config user.name "gatekeeper-evidence[bot]"
git -C "$EVIDENCE_DIR" config user.email "41898282+github-actions[bot]@users.noreply.github.com"

max_attempts=5

publish_checkpoint_summary() {
  if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
    {
      echo '```'
      cat "$EVIDENCE_DIR/checkpoint"
      echo '```'
    } >>"$GITHUB_STEP_SUMMARY"
  fi
}

for attempt in $(seq 1 "$max_attempts"); do
  echo "evidence-push: attempt $attempt/$max_attempts"

  if ! git -C "$EVIDENCE_DIR" fetch origin gatekeeper-evidence; then
    echo "evidence-push: fetch failed" >&2
  elif ! git -C "$EVIDENCE_DIR" reset --hard origin/gatekeeper-evidence; then
    echo "evidence-push: reset failed" >&2
  else
    "$GATEKEEPER_BIN" record \
      --result "$RESULT_FILE" \
      --evidence "$EVIDENCE_DIR" \
      --repo "$REPO" \
      --commit "$COMMIT" \
      --run-url "$RUN_URL" \
      --run-id "$RUN_ID" \
      --run-attempt "$RUN_ATTEMPT"
    record_code=$?

    if [ "$record_code" -eq 3 ]; then
      echo "evidence-push: run $RUN_ID/$RUN_ATTEMPT was already recorded"
      publish_checkpoint_summary
      exit 0
    elif [ "$record_code" -ne 0 ]; then
      # Not a race (those only ever show up as a rejected push): retrying
      # the same inputs against the same log would just fail the same way.
      echo "evidence-push: gatekeeper record exited $record_code, not retrying" >&2
      exit 1
    elif ! git -C "$EVIDENCE_DIR" add -A || ! git -C "$EVIDENCE_DIR" commit -m "evidence: $COMMIT run $RUN_ID/$RUN_ATTEMPT"; then
      echo "evidence-push: git commit failed" >&2
    elif git -C "$EVIDENCE_DIR" push origin "HEAD:gatekeeper-evidence"; then
      echo "evidence-push: pushed"
      publish_checkpoint_summary
      exit 0
    else
      echo "evidence-push: push was rejected (concurrent writer), retrying" >&2
    fi
  fi

  if [ "$attempt" -lt "$max_attempts" ]; then
    delay=$((attempt * attempt * 2 + RANDOM % 5))
    echo "evidence-push: waiting ${delay}s before retrying"
    sleep "$delay"
  fi
done

echo "evidence-push: giving up after $max_attempts attempts" >&2
exit 1
