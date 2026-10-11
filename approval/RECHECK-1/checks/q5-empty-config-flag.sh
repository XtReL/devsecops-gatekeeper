#!/usr/bin/env bash
# Q5. Явно передан пустой --config?
# Проверяется на уровне бинарника (на уровне action пустой вход равен
# "не задан"): `--config ""` и `--config=` для evidence-target и record,
# cwd без .gatekeeper/evidence.json.
# Ожидание: ДО — пустое значение неотличимо от "не передан": evidence-target
#   rc=0 branch=gatekeeper-evidence; record rc=0 (запись добавлена).
#   ПОСЛЕ — rc=2 и "--config is empty" в обоих подкомандах и обеих формах;
#   record не добавляет запись.
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
echo "== Q5 [$LABEL]"
new_key; new_log 1
mkdir -p "$WORK/cwd"
COMMIT=$(printf 'a%.0s' $(seq 1 40))
rec() { # rec <args...> -> REC_RC, REC_ERR
  REC_ERR=$(cd "$WORK/cwd" && GATEKEEPER_SIGNING_KEY="$(cat "$KEY")" "$GK" record \
    --result "$RESULT" --evidence "$EVIDENCE" --repo octo/recheck --commit "$COMMIT" \
    --run-url https://example.invalid/r --run-id "$1" --run-attempt 1 "${@:2}" 2>&1 >/dev/null)
  REC_RC=$?
}
n=0
for form in sep eq; do
  if [ "$form" = sep ]; then cfgargs=(--config ""); else cfgargs=(--config=); fi
  out=$(cd "$WORK/cwd" && "$GK" evidence-target --repo octo/recheck "${cfgargs[@]}" 2>"$WORK/e"); rc=$?
  err=$(cat "$WORK/e")
  echo "  (evidence-target, форма $form: rc=$rc out='$out' err='$err')"
  n=$((n + 1)); rec "$n" "${cfgargs[@]}"
  echo "  (record, форма $form: rc=$REC_RC err='$REC_ERR')"
  if [ "$LABEL" = before ]; then
    expect "evidence-target/$form rc" 0 "$rc"
    expect_match "evidence-target/$form branch" '^branch=gatekeeper-evidence$' "$out"
    expect "record/$form rc" 0 "$REC_RC"
  else
    expect "evidence-target/$form rc" 2 "$rc"
    expect_match "evidence-target/$form сообщение" '--config is empty' "$err"
    expect "evidence-target/$form stdout пуст" "" "$out"
    expect "record/$form rc" 2 "$REC_RC"
    expect_match "record/$form сообщение" '--config is empty' "$REC_ERR"
  fi
done
if [ "$LABEL" = before ]; then expect "записей в журнале" 2 "$(entries_count)"; else expect "записей в журнале" 0 "$(entries_count)"; fi
finish
