#!/usr/bin/env bash
# Q4. Явно передан путь .gatekeeper/evidence.json, а файла нет?
# Ожидание: ДО — путь, совпадающий с умолчанием, неотличим от "не задан":
#   файла нет -> молча эпоха 1 (target rc=0 branch=gatekeeper-evidence;
#   record rc=0, запись добавлена).  ПОСЛЕ — явный путь обязан существовать:
#   target rc!=0 с "no such file", вывода branch нет; record rc!=0, записей 0.
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
echo "== Q4 [$LABEL]"
new_key; new_log 1
mkdir -p "$WORK/cwd"
P=.gatekeeper/evidence.json

run_target "$WORK/cwd" "$P"
echo "  (шаг target: rc=$TARGET_RC out='$TARGET_OUT' err='$TARGET_ERR')"
d=$(cd "$WORK/cwd" && "$GK" evidence-target --repo octo/recheck --config "$P" 2>"$WORK/e"); drc=$?
echo "  (бинарник напрямую: rc=$drc out='$d' err='$(cat "$WORK/e")')"
run_record "$WORK/cwd" "$P"
echo "  (шаг record: rc=$RECORD_RC)"; printf '%s\n' "$RECORD_OUT" | sed 's/^/    | /'

if [ "$LABEL" = before ]; then
  expect "шаг target rc" 0 "$TARGET_RC"
  expect_match "шаг target branch" '^branch=gatekeeper-evidence$' "$TARGET_OUT"
  expect "бинарник rc" 0 "$drc"
  expect "шаг record rc" 0 "$RECORD_RC"
  expect "записей" 1 "$(entries_count)"
else
  [ "$TARGET_RC" -ne 0 ] && expect "шаг target упал" 1 1 || expect "шаг target упал" 1 0
  expect_match "шаг target: сообщение" 'no such file' "$TARGET_ERR"
  expect "шаг target: branch не выведен" "" "$TARGET_OUT"
  expect "бинарник rc" 2 "$drc"
  [ "$RECORD_RC" -ne 0 ] && expect "шаг record упал" 1 1 || expect "шаг record упал" 1 0
  expect "записей" 0 "$(entries_count)"
fi
finish
