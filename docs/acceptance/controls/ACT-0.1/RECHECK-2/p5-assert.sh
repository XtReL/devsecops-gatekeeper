#!/usr/bin/env bash
# ACT-0.1-RECHECK-2, пункт 5: проверка ожиданий из p5-test-branch/EXPECTATIONS.md
# по сохранённым данным прогона (офлайн).
# Использование: p5-assert.sh <run-dir> <run-id>
#   <run-dir> - p5-run-<run-id>/: run-<id>.json, run-<id>-jobs.json (REST API,
#   curl), run-<id>-job-<job-id>-<slug>.log (p5-extract-mcp-logs.py).
# Код выхода: 0 - все ожидания выполнены, 1 - расхождение.
# Первая редакция этого скрипта (p5-fetch-and-assert.sh) скачивала логи сама;
# в окружении приёмки это невозможно (см. p5-extract-mcp-logs.py), загрузка
# вынесена, проверки сохранены. Убрана одна проверка "target-unset:
# evidence-target без --config": она искала текст в теле скрипта шага, а не
# фактический вызов, и проходила бы при любом поведении (вхолостую).
set -uo pipefail
D=${1:?usage: p5-assert.sh <run-dir> <run-id>}
RUN=${2:?usage}
fail=0
expect() { # expect <description> <command...>
  local d=$1; shift
  if "$@"; then echo "ok    $d"; else echo "FAIL  $d"; fail=1; fi
}
J="$D/run-$RUN-jobs.json"
field() { python3 -I -c 'import sys,json; d=json.load(open(sys.argv[1])); print(eval(sys.argv[2], {"d": d}))' "$@"; }
jconcl() { python3 -I -c 'import sys,json; print([j["conclusion"] for j in json.load(open(sys.argv[1]))["jobs"] if j["name"]==sys.argv[2]][0])' "$J" "$1"; }
log_of() { ls "$D"/run-"$RUN"-job-*-"$1".log 2>/dev/null | head -n1; }

expect "прогон: событие push" test "$(field "$D/run-$RUN.json" 'd["event"]')" = push
expect "прогон: ветка test/recheck-2-config" test "$(field "$D/run-$RUN.json" 'd["head_branch"]')" = test/recheck-2-config
expect "прогон: workflow recheck-2-config.yml" test "$(field "$D/run-$RUN.json" 'd["path"]')" = .github/workflows/recheck-2-config.yml
expect "прогон: completed/success" test "$(field "$D/run-$RUN.json" 'd["status"]+"/"+d["conclusion"]')" = completed/success
expect "заданий 5" test "$(field "$J" 'len(d["jobs"])')" = 5
for n in "build" "target, config not set" "target, config empty string" "target, config on committed epoch-2 file" "target, config on a missing path"; do
  expect "задание '$n': success" test "$(jconcl "$n")" = success
done

LB=$(log_of build)
L1=$(log_of target-config-not-set)
L2=$(log_of target-config-empty-string)
L3=$(log_of target-config-on-committed-epoch-2-file)
L4=$(log_of target-config-on-a-missing-path)
for f in "$LB" "$L1" "$L2" "$L3" "$L4"; do expect "лог есть: ${f##*/}" test -s "$f"; done

expect "build: шаг сборки action выполнен" grep -q 'end-action id=build.build;outcome=success' "$LB"
expect "build: бинарник исполняется (gatekeeper version)" grep -q 'gatekeeper 0\.' "$LB"
expect "target-unset: в with: нет config" bash -c '! sed -n "/##\[group\]Run \.\//,/##\[endgroup\]/p" "$0" | grep -q "config:"' "$L1"
expect "target-unset: CONFIG пуст в env шага target" grep -qE 'Z   CONFIG: ?$' "$L1"
expect "target-unset: шаг target success" grep -q 'end-action id=target.target;outcome=success' "$L1"
expect "target-unset: ASSERT OK" grep -q 'RECHECK-2 target-unset: ASSERT OK' "$L1"
expect "target-unset: branch=gatekeeper-evidence" grep -qE 'Z branch=gatekeeper-evidence$' "$L1"
expect "target-unset: origin .../v1" grep -qE 'Z origin=github.com/XtReL/devsecops-gatekeeper/gatekeeper-evidence/v1$' "$L1"
expect "target-empty: CONFIG пуст в env шага target" grep -qE 'Z   CONFIG: ?$' "$L2"
expect "target-empty: шаг target success" grep -q 'end-action id=target.target;outcome=success' "$L2"
expect "target-empty: ASSERT OK" grep -q 'RECHECK-2 target-empty: ASSERT OK' "$L2"
expect "target-empty: branch=gatekeeper-evidence" grep -qE 'Z branch=gatekeeper-evidence$' "$L2"
expect "target-empty: origin .../v1" grep -qE 'Z origin=github.com/XtReL/devsecops-gatekeeper/gatekeeper-evidence/v1$' "$L2"
expect "target-epoch2: CONFIG = test/recheck-2/epoch2.json" grep -qE 'Z   CONFIG: test/recheck-2/epoch2.json$' "$L3"
expect "target-epoch2: шаг target success" grep -q 'end-action id=target.target;outcome=success' "$L3"
expect "target-epoch2: ASSERT OK" grep -q 'RECHECK-2 target-epoch2: ASSERT OK' "$L3"
expect "target-epoch2: branch=gatekeeper-evidence-e2" grep -qE 'Z branch=gatekeeper-evidence-e2$' "$L3"
expect "target-epoch2: origin .../v1/e2" grep -qE 'Z origin=github.com/XtReL/devsecops-gatekeeper/gatekeeper-evidence/v1/e2$' "$L3"
expect "target-missing: CONFIG = test/recheck-2/does-not-exist.json" grep -qE 'Z   CONFIG: test/recheck-2/does-not-exist.json$' "$L4"
expect "target-missing: шаг target failure" grep -q 'end-action id=target.target;outcome=failure' "$L4"
expect "target-missing: причина read config <путь>" grep -q 'gatekeeper evidence-target: evidence: read config test/recheck-2/does-not-exist.json: open test/recheck-2/does-not-exist.json: no such file or directory' "$L4"
expect "target-missing: код 2" grep -q 'Process completed with exit code 2' "$L4"
expect "target-missing: нет ложной причины does not verify" bash -c '! grep -q "does not verify" "$0"' "$L4"
expect "target-missing: ASSERT OK" grep -q 'RECHECK-2 target-missing: ASSERT OK' "$L4"
expect "ни в одном задании шаг record не выполнялся" bash -c '! grep -h "end-action id=[a-z]*.record;" "$@" | grep -vq "outcome=skipped"' _ "$LB" "$L1" "$L2" "$L3" "$L4"

if [ "$fail" -ne 0 ]; then echo "p5: FAIL"; exit 1; fi
echo "p5: OK"
