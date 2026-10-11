#!/usr/bin/env bash
# Q2. Что делает `gatekeeper evidence-target`, если после JSON-объекта в
# файле конфига эпохи есть второй объект?
# Ожидание: ДО — json.Decoder читает только первый объект, второй молча
#   игнорируется: rc=0, branch по первому объекту (эпоха 2).
#   ПОСЛЕ — rc=2, "unexpected data after the JSON object", ни branch, ни origin.
# Контроль: один объект + перевод строки принимается обоими коммитами.
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
echo "== Q2 [$LABEL]"
mkdir -p "$WORK/cwd"
printf '{"epoch":2}\n{"epoch":3}\n' >"$WORK/two.json"
printf '{"epoch":2}\n' >"$WORK/one.json"

out=$(cd "$WORK/cwd" && "$GK" evidence-target --repo octo/recheck --config "$WORK/one.json" 2>"$WORK/e1"); rc=$?
expect "контроль (один объект) rc" 0 "$rc"
expect_match "контроль branch" '^branch=gatekeeper-evidence-e2$' "$out"

out=$(cd "$WORK/cwd" && "$GK" evidence-target --repo octo/recheck --config "$WORK/two.json" 2>"$WORK/e2"); rc=$?
err=$(cat "$WORK/e2"); echo "  (два объекта: rc=$rc stdout='$out' stderr='$err')"
if [ "$LABEL" = before ]; then
  expect "два объекта: rc" 0 "$rc"
  expect_match "два объекта: branch по первому объекту" '^branch=gatekeeper-evidence-e2$' "$out"
else
  expect "два объекта: rc" 2 "$rc"
  expect_match "два объекта: сообщение" 'unexpected data after the JSON object' "$err"
  expect "два объекта: stdout пуст" "" "$out"
fi
# то же через шаг action (mode=target)
run_target "$WORK/cwd" "$WORK/two.json"
echo "  (шаг target: rc=$TARGET_RC out='$TARGET_OUT')"
if [ "$LABEL" = before ]; then expect "шаг target rc" 0 "$TARGET_RC"; else expect "шаг target rc" 2 "$TARGET_RC"; fi
finish
