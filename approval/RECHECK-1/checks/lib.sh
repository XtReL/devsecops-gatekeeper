#!/usr/bin/env bash
# lib.sh — общая обвязка проверок Q1..Q5 (независимая перепроверка RECHECK-1).
# Подключается через `source`. Каждая проверка вызывается как
#   qN-*.sh <before|after> <каталог-дерева-коммита> <бинарник-gatekeeper>
# и завершается кодом 1, если наблюдаемое поведение расходится с выводом,
# сделанным ДО запуска (ожидания записаны в самих проверках).
#
# Шаги action берутся из action.yml проверяемого коммита и исполняются
# так же, как раннер GitHub: bash --noprofile --norc -e -o pipefail.
# Значение незаданного входа — default из того же action.yml.
set -uo pipefail

LABEL=${1:?usage: $0 <before|after> <tree-dir> <gatekeeper-bin>}
TREE=${2:?usage: $0 <before|after> <tree-dir> <gatekeeper-bin>}
GK=${3:?usage: $0 <before|after> <tree-dir> <gatekeeper-bin>}
TREE=$(cd "$TREE" && pwd)
GK=$(cd "$(dirname "$GK")" && pwd)/$(basename "$GK")
ACTION_YML="$TREE/action.yml"
case "$LABEL" in before | after) ;; *) echo "label must be before|after" >&2; exit 2 ;; esac

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

# Изоляция git: ни глобальной, ни системной конфигурации не читаем и не меняем.
export HOME="$WORK/home"
mkdir -p "$HOME"
export GIT_CONFIG_GLOBAL=/dev/null
export GIT_CONFIG_NOSYSTEM=1
unset GIT_AUTHOR_NAME GIT_AUTHOR_EMAIL GIT_COMMITTER_NAME GIT_COMMITTER_EMAIL || true

FAILS=0
# expect <описание> <ожидаемое> <фактическое>
expect() {
  if [ "$2" = "$3" ]; then
    echo "  ok   $1: $3"
  else
    echo "  FAIL $1: ожидалось '$2', получено '$3'"
    FAILS=$((FAILS + 1))
  fi
}
# expect_match <описание> <регэксп> <фактическое>
expect_match() {
  if printf '%s' "$3" | grep -Eq -- "$2"; then
    echo "  ok   $1: найдено /$2/"
  else
    echo "  FAIL $1: нет /$2/ в: $3"
    FAILS=$((FAILS + 1))
  fi
}
finish() {
  if [ "$FAILS" -ne 0 ]; then
    echo "RESULT: FAIL ($FAILS расхождений с ожидаемым выводом) [$LABEL]"
    exit 1
  fi
  echo "RESULT: PASS (наблюдаемое поведение совпало с выводом) [$LABEL]"
  exit 0
}

# input_default <имя входа> — default из action.yml проверяемого коммита.
input_default() {
  python3 -I - "$ACTION_YML" "$1" <<'PY'
import sys, yaml
d = yaml.safe_load(open(sys.argv[1]))
v = d["inputs"][sys.argv[2]].get("default", "")
sys.stdout.write("" if v is None else str(v))
PY
}

# step_script <имя шага> <файл> — тело run: шага из action.yml.
step_script() {
  python3 -I - "$ACTION_YML" "$1" "$2" <<'PY'
import sys, yaml
d = yaml.safe_load(open(sys.argv[1]))
for s in d["runs"]["steps"]:
    if s.get("name") == sys.argv[2]:
        open(sys.argv[3], "w").write(s["run"])
        break
else:
    sys.exit("step not found: " + sys.argv[2])
PY
}

# run_target <cwd> <config|__UNSET__> — исполняет шаг "Resolve evidence target"
# с CONFIG = значение входа (или default из action.yml). Результат:
#   TARGET_RC, TARGET_OUT (содержимое $GITHUB_OUTPUT), TARGET_ERR.
run_target() {
  local cwd=$1 cfg=$2 script="$WORK/target-step.sh" out="$WORK/target.out" err="$WORK/target.err"
  step_script "Resolve evidence target (mode=target)" "$script"
  [ "$cfg" = "__UNSET__" ] && cfg=$(input_default config)
  : >"$out"
  (cd "$cwd" && env GATEKEEPER_BIN="$GK" REPO="octo/recheck" CONFIG="$cfg" GITHUB_OUTPUT="$out" \
    bash --noprofile --norc -e -o pipefail "$script") 2>"$err"
  TARGET_RC=$?
  TARGET_OUT=$(cat "$out")
  TARGET_ERR=$(cat "$err")
}

# new_key — ключ Ed25519 (PKCS#8 PEM) в $WORK/signer.key.
new_key() {
  KEY="$WORK/signer.key"
  openssl genpkey -algorithm ed25519 -out "$KEY" 2>/dev/null
}

# new_log <epoch> — локальный bare-репозиторий с сиротской веткой журнала
# нужной эпохи (evidence-init) и рабочий клон EVIDENCE этой ветки.
new_log() {
  local epoch=$1 branch=gatekeeper-evidence init="$WORK/init-clone"
  [ "$epoch" -ge 2 ] && branch="gatekeeper-evidence-e$epoch"
  ORIGIN="$WORK/origin.git"
  git init --bare -q "$ORIGIN"
  git clone -q "$ORIGIN" "$init" 2>/dev/null
  (cd "$init" && git checkout --orphan "$branch" -q && git rm -rf . -q >/dev/null 2>&1 || true)
  "$GK" evidence-init --evidence "$init" --repo octo/recheck --key "$KEY" --epoch "$epoch" >/dev/null
  (cd "$init" &&
    git -c user.name=init -c user.email=init@example.invalid add -A &&
    git -c user.name=init -c user.email=init@example.invalid commit -q -m init &&
    git push -q origin "$branch")
  EVIDENCE="$WORK/evidence"
  git clone -q --branch "$branch" --single-branch "$ORIGIN" "$EVIDENCE" 2>/dev/null
  RESULT="$WORK/result.json"
  mkdir -p "$WORK/clean-src" && echo "nothing here" >"$WORK/clean-src/readme.txt"
  "$GK" scan --source "$WORK/clean-src" --out "$RESULT" >/dev/null
}

# run_record <cwd> <config|__UNSET__> — исполняет шаг "Record evidence" с ключом
# в env. Результат: RECORD_RC, RECORD_OUT (stdout+stderr).
run_record() {
  local cwd=$1 cfg=$2 script="$WORK/record-step.sh"
  step_script "Record evidence (mode=record)" "$script"
  [ "$cfg" = "__UNSET__" ] && cfg=$(input_default config)
  RECORD_OUT=$(cd "$cwd" && env \
    GATEKEEPER_SIGNING_KEY="$(cat "$KEY")" \
    GATEKEEPER_BIN="$GK" RESULT_FILE="$RESULT" EVIDENCE_DIR="$EVIDENCE" CONFIG="$cfg" \
    REPO="octo/recheck" COMMIT="$(printf 'a%.0s' $(seq 1 40))" \
    RUN_URL="https://example.invalid/runs/1" RUN_ID="1" RUN_ATTEMPT="1" \
    ACTION_PATH="$TREE" GITHUB_STEP_SUMMARY="$WORK/summary.md" \
    bash --noprofile --norc -e -o pipefail "$script" 2>&1)
  RECORD_RC=$?
}

# entries_count — число записей журнала в рабочем клоне EVIDENCE.
entries_count() {
  find "$EVIDENCE/entries" -type f ! -name .gitkeep 2>/dev/null | wc -l | tr -d ' '
}
