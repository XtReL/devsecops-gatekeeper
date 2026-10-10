#!/usr/bin/env bash
# Контроль C24 (ACT-0.1): вход `config` action не доходит до `gatekeeper record`.
# Восстановлено по командам, выполненным в сессии акта. Файлами тогда
# сохранились только record-step.sh и custom.json (лежат рядом).
#
# Использование: c24-config-input-control.sh <gatekeeper-bin> <root-7e2f7b6>
#   <root-7e2f7b6> - копия дерева 7e2f7b6 (git archive): нужны scripts/evidence-push.sh и action.yml.
#
# Без set -e: код 1 в первом случае ожидается.
set -uo pipefail

GK=${1:?usage: c24-config-input-control.sh <gatekeeper-bin> <root>}
ROOT=${2:?usage: c24-config-input-control.sh <gatekeeper-bin> <root>}
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

W=$(mktemp -d)
trap 'rm -rf "$W"' EXIT

export HOME="$W/home" GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_NOSYSTEM=1
mkdir -p "$HOME"

openssl genpkey -algorithm ed25519 -out "$W/k.key" 2>/dev/null

# Журнал эпохи 2: ветка gatekeeper-evidence-e2, origin .../v1/e2.
git init --bare -q "$W/o.git"
git clone -q "$W/o.git" "$W/init" 2>/dev/null
(cd "$W/init" && git checkout --orphan gatekeeper-evidence-e2 -q && (git rm -rf . -q >/dev/null 2>&1 || true))
"$GK" evidence-init --evidence "$W/init" --repo octo/r --key "$W/k.key" --epoch 2
git -C "$W/init" -c user.name=i -c user.email=i@e.invalid add -A
git -C "$W/init" -c user.name=i -c user.email=i@e.invalid commit -qm init
git -C "$W/init" push -q origin gatekeeper-evidence-e2
git clone -q --branch gatekeeper-evidence-e2 "$W/o.git" "$W/ev"

mkdir -p "$W/src" "$W/ws/cfg"
echo hi >"$W/src/a.txt"
"$GK" scan --source "$W/src" --out "$W/res.json"
cp "$HERE/custom.json" "$W/ws/cfg/custom.json" # {"epoch": 2} по нестандартному пути

# Тело шага id=record из action.yml (то же, что в record-step.sh рядом).
python3 -I -c 'import sys,yaml;print([s for s in yaml.safe_load(open(sys.argv[1]))["runs"]["steps"] if s.get("id")=="record"][0]["run"])' \
  "$ROOT/action.yml" >"$W/record-step.sh"

step() {
  # $1 - сколько последних строк вывода показать. Код возврата берётся у шага, а не у tail.
  (cd "$W/ws" &&
    GATEKEEPER_SIGNING_KEY="$(cat "$W/k.key")" GATEKEEPER_BIN="$GK" RESULT_FILE="$W/res.json" \
      EVIDENCE_DIR="$W/ev" CONFIG=cfg/custom.json REPO=octo/r COMMIT="$(printf 'a%.0s' $(seq 40))" \
      RUN_URL=https://example.invalid/r RUN_ID=1 RUN_ATTEMPT=1 ACTION_PATH="$ROOT" \
      bash -eo pipefail "$W/record-step.sh") >"$W/out.txt" 2>&1
  local code=$?
  tail -n "$1" "$W/out.txt"
  echo "record step exit=$code"
}

echo "== case 1: config только по пути cfg/custom.json"
step 3

echo "== case 2: тот же конфиг ещё и по пути по умолчанию"
mkdir -p "$W/ws/.gatekeeper"
cp "$W/ws/cfg/custom.json" "$W/ws/.gatekeeper/evidence.json"
step 1
