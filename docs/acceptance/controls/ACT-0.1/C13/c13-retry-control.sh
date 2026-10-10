#!/usr/bin/env bash
# Контроль C13 (ACT-0.1): ветка повтора в scripts/evidence-push.sh.
# Восстановлено по командам, выполненным в сессии акта. Отдельным файлом
# сценарий тогда не сохранялся. Хук pre-receive лежит рядом, в нём путь
# заменён на __WORK__.
#
# Использование: c13-retry-control.sh <gatekeeper-bin> <trustcore-bin> <root-7e2f7b6>
#   <root-7e2f7b6> - копия дерева 7e2f7b6 (git archive), берётся scripts/evidence-push.sh.
#
# Без set -e: отказ push и код 1 здесь ожидаются.
set -uo pipefail

GK=${1:?usage: c13-retry-control.sh <gatekeeper-bin> <trustcore-bin> <root>}
TC=${2:?usage: c13-retry-control.sh <gatekeeper-bin> <trustcore-bin> <root>}
ROOT=${3:?usage: c13-retry-control.sh <gatekeeper-bin> <trustcore-bin> <root>}
HOOK_SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/pre-receive"

W=$(mktemp -d)
trap 'rm -rf "$W"' EXIT

# Изолированный git: ни глобальной, ни системной конфигурации.
export HOME="$W/home" GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_NOSYSTEM=1
mkdir -p "$HOME"

openssl genpkey -algorithm ed25519 -out "$W/k.key" 2>/dev/null
openssl pkey -in "$W/k.key" -pubout -out "$W/k.pub" 2>/dev/null

git init --bare -q "$W/o.git"
git clone -q "$W/o.git" "$W/init" 2>/dev/null
(cd "$W/init" && git checkout --orphan gatekeeper-evidence -q && (git rm -rf . -q >/dev/null 2>&1 || true))
"$GK" evidence-init --evidence "$W/init" --repo octo/r --key "$W/k.key" >/dev/null
git -C "$W/init" -c user.name=i -c user.email=i@e.invalid add -A
git -C "$W/init" -c user.name=i -c user.email=i@e.invalid commit -qm init
git -C "$W/init" push -q origin gatekeeper-evidence
git clone -q --branch gatekeeper-evidence "$W/o.git" "$W/ev"

mkdir "$W/src"
echo hi >"$W/src/a.txt"
"$GK" scan --source "$W/src" --out "$W/res.json"

# Хук отклоняет первые REJECT_N push (по умолчанию 1).
sed "s#__WORK__#$W#g" "$HOOK_SRC" >"$W/o.git/hooks/pre-receive"
chmod +x "$W/o.git/hooks/pre-receive"

run() {
  GATEKEEPER_SIGNING_KEY="$(cat "$W/k.key")" GATEKEEPER_BIN="$GK" RESULT_FILE="$W/res.json" \
    EVIDENCE_DIR="$1" EVIDENCE_BRANCH=gatekeeper-evidence REPO=octo/r COMMIT="$2" \
    RUN_URL=https://example.invalid/r RUN_ID="$3" RUN_ATTEMPT=1 \
    "$ROOT/scripts/evidence-push.sh"
}

echo "== case 1: хук отклоняет первый push один раз"
start=$(date +%s)
run "$W/ev" "$(printf 'a%.0s' $(seq 40))" 7001 2>&1 | grep -E 'attempt|rejected|waiting|pushed|planted|giving'
echo "pipeline exit=${PIPESTATUS[0]} elapsed=$(($(date +%s) - start))s"
"$TC" verify -log "$W/ev" -origin github.com/octo/r/gatekeeper-evidence/v1 \
  -log-pub "$W/k.pub" -attester-pub "$W/k.pub" 2>&1 | tail -1

echo "== case 2: хук отклоняет всегда (ожидается 5 попыток и код 1)"
echo 0 >"$W/count"
start=$(date +%s)
REJECT_N=99 run "$W/ev" "$(printf 'b%.0s' $(seq 40))" 7002 2>&1 | grep -E 'attempt|waiting|giving'
echo "pipeline exit=${PIPESTATUS[0]} elapsed=$(($(date +%s) - start))s"
