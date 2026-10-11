#!/usr/bin/env bash
# Q3. Что происходит, если config не задан и файла .gatekeeper/evidence.json нет?
# "Не задан" = вход опущен, берётся default из action.yml коммита (ДО это
# '.gatekeeper/evidence.json', ПОСЛЕ — пустая строка).
# Ожидание: оба коммита — эпоха 1: target rc=0, branch=gatekeeper-evidence;
#   record rc=0 и одна запись в журнале эпохи 1.
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
echo "== Q3 [$LABEL] default входа config = '$(input_default config)'"
new_key; new_log 1
mkdir -p "$WORK/cwd"
[ ! -e "$WORK/cwd/.gatekeeper/evidence.json" ] || { echo "fixture broken"; exit 2; }

run_target "$WORK/cwd" __UNSET__
echo "  (target: rc=$TARGET_RC out='$TARGET_OUT' err='$TARGET_ERR')"
expect "target rc" 0 "$TARGET_RC"
expect_match "target branch" '^branch=gatekeeper-evidence$' "$TARGET_OUT"
expect_match "target origin" '^origin=.*gatekeeper-evidence/v1$' "$TARGET_OUT"

run_record "$WORK/cwd" __UNSET__
echo "  (record rc=$RECORD_RC)"; printf '%s\n' "$RECORD_OUT" | sed 's/^/    | /'
expect "record rc" 0 "$RECORD_RC"
expect "записей в журнале эпохи 1" 1 "$(entries_count)"
finish
