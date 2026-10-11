#!/usr/bin/env bash
# ACT-0.1-RECHECK-2: повтор всех контролей приёмки с утверждениями.
# Использование:
#   run-recheck-2.sh <root-ba73ba0> <root-7e2f7b6>            - контроли
#   run-recheck-2.sh --verify                                 - только манифест
# <root-*> - деревья коммитов из git archive, в <root-ba73ba0> заранее собран
# bin/gatekeeper (GOFLAGS=-mod=readonly go build -o bin/gatekeeper ./cmd/gatekeeper).
# Деревья не меняются: каждая проверка работает на своей временной копии.
# Код выхода 0 - все ожидания выполнены, 1 - расхождение.
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CTL="$HERE/.."
ACC="$HERE/../../.."   # docs/acceptance

if [ "${1:-}" = "--verify" ]; then
  (cd "$ACC" && sha256sum -c --quiet ACT-0.1-RECHECK-2.sha256) && echo "run-recheck-2: manifest OK" && exit 0
  echo "run-recheck-2: manifest FAIL"; exit 1
fi

OBJ=$(readlink -f "${1:?usage: run-recheck-2.sh <root-ba73ba0> <root-7e2f7b6> | --verify}")
BASE=$(readlink -f "${2:?usage}")
fail=0
pass() { echo "ok    $*"; }
bad() { echo "FAIL  $*"; fail=1; }
copy_obj() { local w; w=$(mktemp -d); cp -r "$OBJ/." "$w/"; echo "$w"; }
gt() { (cd "$1" && shift && GOFLAGS=-mod=readonly go test -count=1 -v "$@" 2>&1); }

# --- пункт 1: K8 ---------------------------------------------------------
W=$(copy_obj)
out=$(gt "$W" -run '^TestRunRecordRejectsEmptyConfigFlag$' ./cmd/gatekeeper); rc=$?
[ $rc -eq 0 ] && pass "П1 положительный: TestRunRecordRejectsEmptyConfigFlag на объекте PASS" || { bad "П1 положительный: тест на объекте упал"; echo "$out"; }
(cd "$W" && patch -p1 -s <"$CTL/RECHECK-1-mutations/K8.patch") || bad "П1: K8.patch не применился"
out=$(gt "$W" -run '^TestRunRecordRejectsEmptyConfigFlag$' ./cmd/gatekeeper); rc=$?
if [ $rc -ne 0 ] && grep -q 'config_test.go:141: record --config "": expected exit 2' <<<"$out" && ! grep -qE 'build failed|undefined:' <<<"$out"; then
  pass "П1: на K8 тест падает на утверждении config_test.go:141"
else bad "П1: на K8 нет падения на утверждении (rc=$rc)"; echo "$out"; fi
rm -rf "${W:?}"

# --- пункт 2: откат evidence.go и main.go к 7e2f7b6 ----------------------
W=$(copy_obj)
cp "$BASE/internal/evidence/evidence.go" "$W/internal/evidence/evidence.go"
cp "$BASE/cmd/gatekeeper/main.go" "$W/cmd/gatekeeper/main.go"
out=$(gt "$W" -run '^TestRunRecordAppliesCustomConfig$' ./cmd/gatekeeper); rc=$?
if [ $rc -ne 0 ] && grep -q 'main_test.go:306: record with a missing --config failed for the wrong reason' <<<"$out" && grep -q 'does not verify under this log key' <<<"$out"; then
  pass "П2: TestRunRecordAppliesCustomConfig падает на main_test.go:306 (причина does not verify)"
else bad "П2: TestRunRecordAppliesCustomConfig (rc=$rc)"; echo "$out"; fi
out=$(gt "$W" -run '^TestRecordRejectsMissingNamedConfig$' ./internal/evidence); rc=$?
if [ $rc -ne 0 ] && grep -q 'evidence_test.go:664: Record succeeded with a missing named config' <<<"$out"; then
  pass "П2: TestRecordRejectsMissingNamedConfig падает на evidence_test.go:664"
else bad "П2: TestRecordRejectsMissingNamedConfig (rc=$rc)"; echo "$out"; fi
rm -rf "${W:?}"
out=$(gt "$OBJ" -run '^(TestRunRecordAppliesCustomConfig)$' ./cmd/gatekeeper && gt "$OBJ" -run '^(TestRecordRejectsMissingNamedConfig)$' ./internal/evidence); rc=$?
[ $rc -eq 0 ] && pass "П2 положительный: оба теста на объекте PASS" || { bad "П2 положительный (rc=$rc)"; echo "$out"; }

# --- пункт 5: офлайн-проверка сохранённого прогона -----------------------
bash "$HERE/p5-assert.sh" "$HERE/p5-run-38162383246" 38162383246 >/dev/null && pass "П5: p5-assert.sh по сохранённому прогону 38162383246" || bad "П5: p5-assert.sh"

# --- пункт 6: C23 и C24 ---------------------------------------------------
bash "$CTL/C23/c23-config-strict-repro.sh" "$OBJ/bin/gatekeeper" "$OBJ" fixed >/dev/null 2>&1 && pass "П6: C23 fixed на объекте: код 0" || bad "П6: C23 fixed"
bash "$CTL/C23/c23-config-strict-repro.sh" "$OBJ/bin/gatekeeper" "$OBJ" defect >/dev/null 2>&1 && bad "П6: C23 defect на объекте не упал" || pass "П6: C23 defect на объекте: код 1 (контроль умеет упасть)"
bash "$CTL/C24/c24-recheck-assert.sh" "$OBJ/bin/gatekeeper" "$OBJ" fixed >/dev/null 2>&1 && pass "П6: C24 fixed на объекте: код 0" || bad "П6: C24 fixed"
bash "$CTL/C24/c24-recheck-assert.sh" "$OBJ/bin/gatekeeper" "$OBJ" defect >/dev/null 2>&1 && bad "П6: C24 defect на объекте не упал" || pass "П6: C24 defect на объекте: код 1 (контроль умеет упасть)"

if [ "$fail" -ne 0 ]; then echo "run-recheck-2: FAIL"; exit 1; fi
echo "run-recheck-2: OK"
