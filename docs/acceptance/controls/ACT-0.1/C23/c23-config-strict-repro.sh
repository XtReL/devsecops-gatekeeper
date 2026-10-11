#!/usr/bin/env bash
# Репродуктор дефекта C23 (ACT-0.1): конфиг эпохи принимается нестрого.
#   1) хвост после JSON-объекта молча игнорируется ({"epoch":2}{"epoch":5});
#   2) отсутствующий файл по явно переданному пути даёт эпоху 1 (а не ошибку).
# Плюс границы исправления: путь по умолчанию, заданный явно, и явный пустой
# --config; положительные контроли, которые исправление ломать не должно.
#
# Использование:
#   c23-config-strict-repro.sh <gatekeeper-bin> <root> <defect|fixed>
#     <root>  - дерево проверяемого коммита (git archive): из него берётся action.yml.
#     defect  - ожидается поведение 7e2f7b6 (дефект присутствует);
#     fixed   - ожидается поведение f7c2cfe (дефект устранён).
# Код выхода: 0 - все случаи совпали с ожиданием выбранного режима, 1 - есть расхождение.
# Ожидание проверяется внутри скрипта (контроль обязан уметь упасть, методика 8.2).
#
# Ключ для случаев F создаётся на месте и удаляется вместе с каталогом. Значения не выводятся.
set -uo pipefail

GK=${1:?usage: c23-config-strict-repro.sh <gatekeeper-bin> <root> <defect|fixed>}
ROOT=${2:?usage: c23-config-strict-repro.sh <gatekeeper-bin> <root> <defect|fixed>}
MODE=${3:?usage: c23-config-strict-repro.sh <gatekeeper-bin> <root> <defect|fixed>}
case "$MODE" in defect | fixed) ;; *)
  echo "mode must be defect or fixed" >&2
  exit 2
  ;; esac
GK=$(readlink -f "$GK")
ROOT=$(readlink -f "$ROOT")

W=$(mktemp -d)
trap 'rm -rf "$W"' EXIT
export HOME="$W/home" GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_NOSYSTEM=1
mkdir -p "$HOME"

openssl genpkey -algorithm ed25519 -out "$W/k.key" 2>/dev/null
mkdir -p "$W/src"
echo hi >"$W/src/a.txt"
"$GK" scan --source "$W/src" --out "$W/res.json" >/dev/null 2>&1 || true

fails=0
total=0

# cwd для каждого случая - свежий пустой каталог (в нём нет .gatekeeper/evidence.json,
# если случай сам его не создаёт).
newdir() {
  mktemp -d -p "$W" case.XXXXXX
}

# check <id> <описание> <ожидание-defect> <ожидание-fixed> <фактический код> <фактическая ветка> [stderr-файл] [подстрока-в-stderr]
#   ожидание: "КОД" или "КОД:ветка"; КОД "!0" = любой ненулевой.
check() {
  local id=$1 desc=$2 exp_d=$3 exp_f=$4 code=$5 branch=$6 errf=${7:-} want_err=${8:-}
  local exp=$exp_d
  [ "$MODE" = fixed ] && exp=$exp_f
  local exp_code=${exp%%:*} exp_branch=""
  [[ "$exp" == *:* ]] && exp_branch=${exp#*:}
  local ok=1
  if [ "$exp_code" = '!0' ]; then
    [ "$code" -ne 0 ] || ok=0
  else
    [ "$code" -eq "$exp_code" ] || ok=0
  fi
  if [ -n "$exp_branch" ] && [ "$branch" != "$exp_branch" ]; then ok=0; fi
  if [ -n "$want_err" ] && [ "$MODE" = fixed ] && [ "$exp_code" != 0 ]; then
    grep -q -- "$want_err" "$errf" || ok=0 # причина отказа названа верно, а не любая ошибка
  fi
  total=$((total + 1))
  if [ "$ok" -eq 1 ]; then
    printf 'ok    %-3s %-62s exit=%s branch=%s\n' "$id" "$desc" "$code" "${branch:--}"
  else
    printf 'FAIL  %-3s %-62s exit=%s branch=%s (ожидалось в режиме %s: %s)\n' "$id" "$desc" "$code" "${branch:--}" "$MODE" "$exp"
    [ -n "$errf" ] && sed 's/^/        stderr: /' "$errf" | head -3
    fails=$((fails + 1))
  fi
}

# target <id> <описание> <ожид-defect> <ожид-fixed> <dir> <args...>
target() {
  local id=$1 desc=$2 ed=$3 ef=$4 dir=$5
  shift 5
  local out err code
  out="$W/out.$id"
  err="$W/err.$id"
  (cd "$dir" && "$GK" evidence-target --repo octo/r "$@") >"$out" 2>"$err"
  code=$?
  check "$id" "$desc" "$ed" "$ef" "$code" "$(sed -n 's/^branch=//p' "$out")" "$err" "config"
}

E1=gatekeeper-evidence
E2=gatekeeper-evidence-e2
E3=gatekeeper-evidence-e3

echo "== режим: $MODE; gatekeeper: $("$GK" 2>&1 | head -1 | cut -c1-60)"

echo "-- A. хвост после JSON-объекта"
d=$(newdir)
printf '{"epoch":2}{"epoch":5}' >"$d/t.json"
target A1 'хвост: второй объект {"epoch":2}{"epoch":5}' "0:$E2" 2 "$d" --config t.json
printf '{"epoch":2} garbage' >"$d/g.json"
target A2 'хвост: посторонний текст' "0:$E2" 2 "$d" --config g.json
printf '{"epoch":2}\n\n  \t\n' >"$d/ok.json"
target A3 '[положит. контроль] пробелы и перевод строки после объекта' "0:$E2" "0:$E2" "$d" --config ok.json

echo "-- B. отсутствующий файл по явному пути"
d=$(newdir)
target B1 'явный --config /nonexistent.json' "0:$E1" 2 "$d" --config /nonexistent.json
target B2 'явный относительный путь с опечаткой cfg/typo.json' "0:$E1" 2 "$d" --config cfg/typo.json

echo "-- C. --config не передан"
d=$(newdir)
target C1 '[положит. контроль] флага нет, файла нет: эпоха 1' "0:$E1" "0:$E1" "$d"
mkdir -p "$d/.gatekeeper"
printf '{"epoch":3}' >"$d/.gatekeeper/evidence.json"
target C2 '[положит. контроль] флага нет, файл по умолчанию есть: читается' "0:$E3" "0:$E3" "$d"

echo "-- D. путь по умолчанию задан явно"
d=$(newdir)
target D1 'явно .gatekeeper/evidence.json, файла нет' "0:$E1" 2 "$d" --config .gatekeeper/evidence.json
mkdir -p "$d/.gatekeeper"
printf '{"epoch":3}' >"$d/.gatekeeper/evidence.json"
target D2 '[положит. контроль] явно .gatekeeper/evidence.json, файл есть' "0:$E3" "0:$E3" "$d" --config .gatekeeper/evidence.json

echo "-- E. явный пустой --config"
d=$(newdir)
target E1 '--config "" (два аргумента), файла по умолчанию нет' "0:$E1" 2 "$d" --config ""
target E2 '--config= (один аргумент), файла по умолчанию нет' "0:$E1" 2 "$d" --config=
mkdir -p "$d/.gatekeeper"
printf '{"epoch":3}' >"$d/.gatekeeper/evidence.json"
target E3 '--config "", файл по умолчанию есть (откат на него недопустим)' "0:$E3" 2 "$d" --config ""

echo "-- F. тот же дефект в record (журнал эпохи 1 есть, конфиг указан неверно)"
rec() { # rec <id> <описание> <ожид-defect> <ожид-fixed> <run-id> <args...>
  local id=$1 desc=$2 ed=$3 ef=$4 rid=$5
  shift 5
  local dir ev err code
  dir=$(newdir)
  ev="$W/ev.$id"
  err="$W/err.$id"
  "$GK" evidence-init --evidence "$ev" --repo octo/r --key "$W/k.key" >/dev/null 2>&1
  (cd "$dir" && GATEKEEPER_SIGNING_KEY="$(cat "$W/k.key")" "$GK" record \
    --result "$W/res.json" --evidence "$ev" --repo octo/r \
    --commit "$(printf 'b%.0s' $(seq 40))" --run-url https://example.invalid/r \
    --run-id "$rid" --run-attempt 1 "$@") >/dev/null 2>"$err"
  code=$?
  check "$id" "$desc" "$ed" "$ef" "$code" "" "$err" "config"
}
rec F1 'record --config cfg/typo.json (файла нет)' 0 2 9201 --config cfg/typo.json
rec F2 'record --config "" ' 0 2 9202 --config ""
rec F3 '[положит. контроль] record без --config, файла нет: эпоха 1' 0 0 9203

echo "-- G. тело шага target из action.yml и значение входа config по умолчанию"
step="$W/target-step.sh"
python3 -I -c 'import sys,yaml;print([s for s in yaml.safe_load(open(sys.argv[1]))["runs"]["steps"] if s.get("id")=="target"][0]["run"])' "$ROOT/action.yml" >"$step"
def_in=$(python3 -I -c 'import sys,yaml;print(yaml.safe_load(open(sys.argv[1]))["inputs"]["config"]["default"])' "$ROOT/action.yml")
gstep() { # gstep <id> <описание> <ожид-defect> <ожид-fixed> <CONFIG>
  local id=$1 desc=$2 ed=$3 ef=$4 cfg=$5 dir out err code
  dir=$(newdir)
  out="$W/gh.$id"
  err="$W/err.$id"
  : >"$out"
  (cd "$dir" && GITHUB_OUTPUT="$out" GATEKEEPER_BIN="$GK" REPO=octo/r CONFIG="$cfg" bash -eo pipefail "$step") >/dev/null 2>"$err"
  code=$?
  check "$id" "$desc" "$ed" "$ef" "$code" "$(sed -n 's/^branch=//p' "$out")" "$err" ""
}
gstep G1 'шаг target, CONFIG="" , файла нет' "0:$E1" "0:$E1" ""
gstep G2 'шаг target, CONFIG=.gatekeeper/evidence.json, файла нет' "0:$E1" '!0' ".gatekeeper/evidence.json"
total=$((total + 1))
want_def=".gatekeeper/evidence.json"
[ "$MODE" = fixed ] && want_def=""
if [ "$def_in" = "$want_def" ]; then
  printf 'ok    %-3s %-62s default=%q\n' G3 'значение по умолчанию входа config в action.yml' "$def_in"
else
  printf 'FAIL  %-3s %-62s default=%q (ожидалось %q)\n' G3 'значение по умолчанию входа config в action.yml' "$def_in" "$want_def"
  fails=$((fails + 1))
fi

echo "== итог: случаев $total, расхождений с ожиданием режима $MODE: $fails"
[ "$fails" -eq 0 ]
