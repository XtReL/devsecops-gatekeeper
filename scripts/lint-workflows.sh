#!/usr/bin/env bash
# lint-workflows.sh — ADR 0001 forbids workflow_run and pull_request_target
# anywhere in .github/workflows/ (they pass an installation token through
# data from unreviewed PR code; see "Связанное" in the ADR). Used by
# ci.yml's "Forbid dangerous workflow triggers" step and by scripts/check.sh.
#
# The words are assembled from parts, not written literally in this file,
# so this step never flags itself when it greps non-comment lines, and so
# the error message doesn't contain them either.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

w1="workflow"; w1="${w1}_run"
w2="pull_request"; w2="${w2}_target"
pattern="${w1}|${w2}"

hit=0
shopt -s nullglob
for f in .github/workflows/*.yml .github/workflows/*.yaml; do
  [ -f "$f" ] || continue
  if grep -vE '^[[:space:]]*#' "$f" | grep -qE "$pattern"; then
    echo "::error file=$f::forbidden CI trigger keyword found (see ADR 0001)"
    hit=1
  fi
done

if [ "$hit" -ne 0 ]; then
  exit 1
fi
