# GATEKEEPER_SIGNING_KEY is read from the ambient environment set by
# the caller's own uses: step (see the header comment above). It is
# never printed, including in this error message.
if [ -z "${GATEKEEPER_SIGNING_KEY:-}" ]; then
  echo "::error::GATEKEEPER_SIGNING_KEY is empty or not set (must be provided via env: on this step, in mode: record only)"
  exit 1
fi

EVIDENCE_BRANCH="$("$GATEKEEPER_BIN" evidence-target --repo "$REPO" --config "$CONFIG" | sed -n 's/^branch=//p')"
if [ -z "$EVIDENCE_BRANCH" ]; then
  echo "::error::could not resolve the evidence branch"
  exit 1
fi
export EVIDENCE_BRANCH

"$ACTION_PATH/scripts/evidence-push.sh"

