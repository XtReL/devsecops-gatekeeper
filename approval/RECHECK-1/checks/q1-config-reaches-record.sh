#!/usr/bin/env bash
# Q1. Доходит ли вход config из action.yml до режима record?
# Фикстура: журнал эпохи 2 (ветка gatekeeper-evidence-e2), конфиг {"epoch":2}
# вне каталога запуска; в cwd шага нет .gatekeeper/evidence.json.
# Ожидание (выведено из diff до запуска):
#   target: оба коммита передают config в evidence-target -> branch=...-e2.
#   record: ДО — CONFIG используется только для вычисления ветки, в
#     `gatekeeper record` (через evidence-push.sh) не передаётся, record
#     читает конфиг по умолчанию (эпоха 1) и не может писать в журнал эпохи 2:
#     шаг падает, записей 0.  ПОСЛЕ — EVIDENCE_CONFIG -> --config: rc=0, записей 1.
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
echo "== Q1 [$LABEL]"
new_key; new_log 2
mkdir -p "$WORK/cfg" "$WORK/cwd"
echo '{"epoch":2}' >"$WORK/cfg/epoch2.json"

run_target "$WORK/cwd" "$WORK/cfg/epoch2.json"
expect "target rc" 0 "$TARGET_RC"
expect_match "target branch" '^branch=gatekeeper-evidence-e2$' "$TARGET_OUT"

run_record "$WORK/cwd" "$WORK/cfg/epoch2.json"
echo "  (record rc=$RECORD_RC; вывод шага ниже)"; printf '%s\n' "$RECORD_OUT" | sed 's/^/    | /'
if [ "$LABEL" = before ]; then
  [ "$RECORD_RC" -ne 0 ] && expect "record: шаг упал" 1 1 || expect "record: шаг упал" 1 0
  expect "записей в журнале эпохи 2" 0 "$(entries_count)"
else
  expect "record rc" 0 "$RECORD_RC"
  expect "записей в журнале эпохи 2" 1 "$(entries_count)"
fi
finish
