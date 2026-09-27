#!/usr/bin/env bash
# check.sh — runs exactly what ci.yml and gatekeeper.yml run, in the same
# order, and stops at the first failure (set -e does this: nothing here
# swallows a non-zero exit). Run this before every push.
#
# Not reproduced here: ci.yml's "GitGuardian Shield Scan" (GitGuardian/
# ggshield-action). It needs GITGUARDIAN_API_KEY, a secret this script has
# no access to, so it only runs in CI.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

# Kept in sync with the pinned gosec action version in .github/workflows/ci.yml.
GOSEC_VERSION="v2.29.0"

cleanup_paths=()
cleanup() {
  local p
  for p in "${cleanup_paths[@]:-}"; do
    [ -n "$p" ] && rm -rf "$p"
  done
}
trap cleanup EXIT

echo "check: gofmt -l ."
unformatted="$(gofmt -l .)"
if [ -n "$unformatted" ]; then
  echo "$unformatted" >&2
  echo "check: gofmt found unformatted files" >&2
  exit 1
fi

echo "check: go vet ./..."
go vet ./...

echo "check: go test -race -timeout 30s ./..."
go test -race -timeout 30s ./...

echo "check: verify production compilation"
build_dir="$(mktemp -d)"
cleanup_paths+=("$build_dir")
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-w -s" -o "$build_dir/gateway" ./cmd/api/main.go

echo "check: gosec $GOSEC_VERSION -exclude=G104,G108 ./..."
go run "github.com/securego/gosec/v2/cmd/gosec@${GOSEC_VERSION}" -exclude=G104,G108 ./...

echo "check: scripts/lint-workflows.sh"
scripts/lint-workflows.sh

echo "check: self-scan (go run ./cmd/gatekeeper scan --source .)"
selfscan_out="$(mktemp)"
cleanup_paths+=("$selfscan_out")
go run ./cmd/gatekeeper scan --source . --out "$selfscan_out"

echo "check: verify gitleaks version is embedded in scan result"
expected_gitleaks="$(go list -m -f '{{.Version}}' github.com/zricethezav/gitleaks/v8)"
actual_gitleaks="$(sed -n 's/.*"gitleaksVersion": *"\([^"]*\)".*/\1/p' "$selfscan_out" | head -n1)"
if [ -z "$actual_gitleaks" ] || [ "$actual_gitleaks" != "$expected_gitleaks" ]; then
  echo "check: gitleaksVersion in result.json ($actual_gitleaks) does not match go.mod ($expected_gitleaks)" >&2
  exit 1
fi

echo "check: scripts/evidence-push_test.sh"
bin_dir="$(mktemp -d)"
cleanup_paths+=("$bin_dir")
GOFLAGS=-mod=readonly go build -o "$bin_dir/gatekeeper" ./cmd/gatekeeper
GOFLAGS=-mod=readonly go build -o "$bin_dir/trustcore" github.com/XtReL/trust-core/cmd/trustcore
scripts/evidence-push_test.sh "$bin_dir/gatekeeper" "$bin_dir/trustcore"

echo "check: OK"
