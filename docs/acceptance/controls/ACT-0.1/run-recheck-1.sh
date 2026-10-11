#!/usr/bin/env bash
# Запуск контролей RECHECK-1 (ACT-0.1-RECHECK-1) со сверкой sha256.
# Использование: run-recheck-1.sh <root-7e2f7b6> <root-f7c2cfe> <trustcore-bin>
#   <root-*> - деревья коммитов (git archive); в каждом собирается bin/gatekeeper, если его нет.
# Код выхода 0 - хэши сошлись и все 8 прогонов дали ожидаемое.
set -uo pipefail
OLD=$(readlink -f "${1:?usage: run-recheck-1.sh <root-7e2f7b6> <root-f7c2cfe> <trustcore-bin>}")
NEW=$(readlink -f "${2:?usage}")
TC=$(readlink -f "${3:?usage}")
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
rc=0

echo "== sha256 файлов RECHECK-1 (SHA256SUMS)"
(cd "$HERE" && sha256sum -c SHA256SUMS) || { echo "хэши не сошлись, дальше не идём" >&2; exit 1; }

for r in "$OLD" "$NEW"; do
  [ -x "$r/bin/gatekeeper" ] || (cd "$r" && GOFLAGS=-mod=readonly go build -o bin/gatekeeper ./cmd/gatekeeper) || exit 1
done

run() { # run <название> <ожидаемый код> <команда...>
  local name=$1 want=$2
  shift 2
  "$@" >/dev/null 2>&1
  local got=$?
  if [ "$got" -eq "$want" ]; then echo "ok    $name (код $got)"; else echo "FAIL  $name: код $got, ожидался $want"; rc=1; fi
}

C23="$HERE/C23/c23-config-strict-repro.sh"
C24="$HERE/C24/c24-recheck-assert.sh"
# Репродуктор должен подтвердить дефект на старом коде, отсутствие дефекта на новом, и упасть при перекрёстном ожидании.
run "C23 7e2f7b6 defect (дефект есть)"       0 bash "$C23" "$OLD/bin/gatekeeper" "$OLD" defect
run "C23 f7c2cfe fixed  (дефекта нет)"       0 bash "$C23" "$NEW/bin/gatekeeper" "$NEW" fixed
run "C23 7e2f7b6 fixed  (обязан упасть)"     1 bash "$C23" "$OLD/bin/gatekeeper" "$OLD" fixed
run "C23 f7c2cfe defect (обязан упасть)"     1 bash "$C23" "$NEW/bin/gatekeeper" "$NEW" defect
run "C24 7e2f7b6 defect (дефект есть)"       0 bash "$C24" "$OLD/bin/gatekeeper" "$OLD" defect
run "C24 f7c2cfe fixed  (дефекта нет)"       0 bash "$C24" "$NEW/bin/gatekeeper" "$NEW" fixed
run "C24 7e2f7b6 fixed  (обязан упасть)"     1 bash "$C24" "$OLD/bin/gatekeeper" "$OLD" fixed
run "C24 f7c2cfe defect (обязан упасть)"     1 bash "$C24" "$NEW/bin/gatekeeper" "$NEW" defect
[ "$rc" -eq 0 ] && echo "run-recheck-1: OK" || echo "run-recheck-1: есть расхождения"
exit "$rc"
