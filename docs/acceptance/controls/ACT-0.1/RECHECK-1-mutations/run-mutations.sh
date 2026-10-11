#!/usr/bin/env bash
# Целевые мутации исправления C23/C24 (ACT-0.1-RECHECK-1).
# Использование: run-mutations.sh <root-f7c2cfe> <trustcore-bin> [K1 K2 ...]
#   <root-f7c2cfe> - дерево f7c2cfe (git archive), не изменяется: каждая мутация применяется к копии.
# Для каждой мутации Kn.patch (diff к f7c2cfe) запускаются четыре слоя проверок на мутировавшей копии:
#   GO   - go test -count=1 ./cmd/gatekeeper ./internal/evidence
#   SH   - scripts/evidence-push_test.sh
#   C24  - controls/ACT-0.1/C24/c24-recheck-assert.sh ... fixed
#   C23  - controls/ACT-0.1/C23/c23-config-strict-repro.sh ... fixed
# Исход слоя (методика 8.4): KILLED - упало утверждение (--- FAIL, FAIL:, ASSERT FAIL, шаг записи отказал);
#   SURVIVED - слой зелёный; BUILD - не компилируется; TIMEOUT; ENV - сбой окружения.
# Засчитывается только KILLED. Определение исхода по тексту вывода: лог каждого слоя сохраняется в $OUT.
set -uo pipefail
ROOT=$(readlink -f "${1:?usage: run-mutations.sh <root-f7c2cfe> <trustcore-bin> [K..]}")
TC=$(readlink -f "${2:?usage}")
shift 2
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CTL="$HERE/.."
OUT=${OUT:-$(mktemp -d)}
mkdir -p "$OUT"
muts=("$@")
[ "${#muts[@]}" -gt 0 ] || muts=(K1 K2 K3 K4 K5 K6 K7 K8 K9)

verdict() { # verdict <exit> <log> <pattern-of-assertion>
  local code=$1 log=$2 pat=$3
  if [ "$code" -eq 0 ]; then echo SURVIVED; return; fi
  if [ "$code" -eq 124 ]; then echo TIMEOUT; return; fi
  if grep -qE '\[build failed\]|cannot find|undefined:|syntax error' "$log" && ! grep -qE -- "$pat" "$log"; then echo BUILD; return; fi
  if grep -qE -- "$pat" "$log"; then echo KILLED; return; fi
  echo ENV
}

for k in "${muts[@]}"; do
  W=$(mktemp -d)
  cp -r "$ROOT/." "$W/"
  (cd "$W" && patch -p1 -s <"$HERE/$k.patch") || { echo "$k: patch не применился"; continue; }
  (cd "$W" && GOFLAGS=-mod=readonly go build -o bin/gatekeeper ./cmd/gatekeeper) >"$OUT/$k.build.log" 2>&1 || { echo "$k BUILD (go build)"; continue; }
  (cd "$W" && timeout 300 env GOFLAGS=-mod=readonly go test -count=1 ./cmd/gatekeeper ./internal/evidence) >"$OUT/$k.go.log" 2>&1
  go=$(verdict $? "$OUT/$k.go.log" '^--- FAIL|^    --- FAIL|^FAIL')
  (cd "$W" && timeout 300 bash scripts/evidence-push_test.sh "$W/bin/gatekeeper" "$TC") >"$OUT/$k.sh.log" 2>&1
  sh=$(verdict $? "$OUT/$k.sh.log" 'FAIL:|not retrying|does not verify|giving up')
  timeout 300 bash "$CTL/C24/c24-recheck-assert.sh" "$W/bin/gatekeeper" "$W" fixed >"$OUT/$k.c24.log" 2>&1
  c24=$(verdict $? "$OUT/$k.c24.log" 'ASSERT FAIL')
  timeout 300 bash "$CTL/C23/c23-config-strict-repro.sh" "$W/bin/gatekeeper" "$W" fixed >"$OUT/$k.c23.log" 2>&1
  c23=$(verdict $? "$OUT/$k.c23.log" '^FAIL ')
  printf '%-3s GO=%-8s SH=%-8s C24=%-8s C23=%-8s  %s\n' "$k" "$go" "$sh" "$c24" "$c23" "$(cat "$HERE/$k.txt")"
  rm -rf "$W"
done
