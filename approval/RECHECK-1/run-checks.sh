#!/usr/bin/env bash
# run-checks.sh <before-tree> <before-bin> <after-tree> <after-bin> <logs-dir>
# Прогоняет Q1..Q5 на обоих коммитах (logs/qN-<label>.log) и негативный
# контроль: те же проверки с ПЕРЕПУТАННЫМ ярлыком (ожидания "до" на дереве
# "после" и наоборот) обязаны завершаться кодом 1 (logs/negctl-qN-*.log).
set -uo pipefail
BT=$1; BB=$2; AT=$3; AB=$4; LOGS=$5
HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
mkdir -p "$LOGS"
rc=0
for q in q1 q2 q3 q4 q5; do
  f=$(ls "$HERE"/checks/$q-*.sh)
  "$f" before "$BT" "$BB" >"$LOGS/$q-before.log" 2>&1; b=$?
  "$f" after "$AT" "$AB" >"$LOGS/$q-after.log" 2>&1; a=$?
  echo "$q: before exit=$b, after exit=$a"
  [ $b -eq 0 ] && [ $a -eq 0 ] || rc=1
  # негативный контроль
  "$f" before "$AT" "$AB" >"$LOGS/negctl-$q-before-expectations-on-after-tree.log" 2>&1; nb=$?
  "$f" after "$BT" "$BB" >"$LOGS/negctl-$q-after-expectations-on-before-tree.log" 2>&1; na=$?
  echo "$q negctl: exit=$nb / $na (ожидается 1 / 1, кроме Q3 — там поведение совпадает: 0 / 0)"
  if [ "$q" = q3 ]; then
    [ $nb -eq 0 ] && [ $na -eq 0 ] || rc=1
  else
    [ $nb -eq 1 ] && [ $na -eq 1 ] || rc=1
  fi
done
echo "run-checks: rc=$rc"
exit $rc
