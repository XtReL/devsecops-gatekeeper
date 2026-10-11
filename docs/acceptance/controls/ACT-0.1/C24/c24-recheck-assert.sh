#!/usr/bin/env bash
# Обёртка с утверждениями над сохранённым контролем c24-config-input-control.sh
# (ACT-0.1-RECHECK-1). Сам контроль только печатает "record step exit=N" и
# всегда завершается кодом 0, поэтому упасть он не может (методика 8.2).
# Здесь результат проверяется внутри: код 1, если шаг record вёл себя не так, как
# ожидает выбранный режим.
#
# Использование: c24-recheck-assert.sh <gatekeeper-bin> <root> <defect|fixed>
#   defect - ожидается поведение 7e2f7b6: случай 1 -> record step exit=1
#            ("current checkpoint does not verify under this log key"), случай 2 -> exit=0;
#   fixed  - ожидается поведение f7c2cfe: случай 1 -> exit=0 (запись добавлена), случай 2 -> exit=0.
# Случай 2 на исправленном коде идёт после случая 1 с теми же run-id/run-attempt, поэтому он
# даёт "already recorded" (код 0 по идемпотентности) и независимой информации не несёт.
set -uo pipefail
GK=${1:?usage: c24-recheck-assert.sh <gatekeeper-bin> <root> <defect|fixed>}
ROOT=${2:?usage: c24-recheck-assert.sh <gatekeeper-bin> <root> <defect|fixed>}
MODE=${3:?usage: c24-recheck-assert.sh <gatekeeper-bin> <root> <defect|fixed>}
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

log=$(mktemp)
trap 'rm -f "$log"' EXIT
bash "$HERE/c24-config-input-control.sh" "$GK" "$ROOT" >"$log" 2>&1
cat "$log"

# коды шагов в порядке появления: случай 1, случай 2
mapfile -t codes < <(sed -n 's/^record step exit=//p' "$log")
want1=0
[ "$MODE" = defect ] && want1=1
rc=0
if [ "${#codes[@]}" -ne 2 ]; then
  echo "ASSERT FAIL: ожидалось 2 строки 'record step exit=', получено ${#codes[@]} (контроль не дошёл до конца)" >&2
  rc=1
else
  [ "${codes[0]}" = "$want1" ] || { echo "ASSERT FAIL: случай 1: код ${codes[0]}, ожидался $want1 (режим $MODE)" >&2; rc=1; }
  [ "${codes[1]}" = 0 ] || { echo "ASSERT FAIL: случай 2: код ${codes[1]}, ожидался 0" >&2; rc=1; }
  if [ "$MODE" = defect ]; then
    grep -q 'current checkpoint does not verify under this log key' "$log" ||
      { echo "ASSERT FAIL: в случае 1 нет ожидаемого сообщения об отказе" >&2; rc=1; }
  fi
fi
[ "$rc" -eq 0 ] && echo "ASSERT OK (режим $MODE): случай 1 exit=${codes[0]}, случай 2 exit=${codes[1]}"
exit "$rc"
