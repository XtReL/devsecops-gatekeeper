# TASK: composite action Gatekeeper (ADR 0003)

Прочитай `CLAUDE.md`, `docs/adr/0001-action-evidence.md` и `docs/adr/0003-distribution.md`. Решения ADR не меняй; при неясности — остановись и спроси. Один PR в `main`, не сливать.

## Правила безопасности (обязательны, проверяются на ревью)
- **Входы action никогда не подставляются в `run:` через `${{ inputs.… }}`.** Каждый вход передаётся в шаг через `env:` и используется как `"$VAR"`. То же для `${{ github.… }}` внутри `run:`.
- **Ключ `GATEKEEPER_SIGNING_KEY` не является входом action.** Он читается только из окружения и только в режиме `record`; никогда не выводится, не пишется на диск, не передаётся в другие шаги.
- **В режиме `record` нет установки Go, загрузки модулей и сборки.** Только запуск готового бинарника и `evidence-push.sh`.
- Все сторонние actions — по полному SHA с тегом в комментарии.

## 1. `action.yml` в корне
- `name`: `Gatekeeper Evidence` (уникальность для Marketplace проверяется на этапе 5); `description` ≤ 125 символов; `branding` (`icon: shield`, `color: green`).
- `runs.using: composite`. Вход `mode` (обязательный): `build` | `scan` | `target` | `record`; неизвестное значение — ошибка.
- Прочие входы: `source` (по умолчанию `.`), `gatekeeper` (путь к бинарнику), `result` (путь к `result.json`), `evidence` (по умолчанию `evidence`), `config` (по умолчанию `.gatekeeper/evidence.json`).
- **`build`:** `actions/setup-go` (по SHA) с `go-version-file: ${{ github.action_path }}/go.mod`, встроенный кэш с `cache-dependency-path: ${{ github.action_path }}/go.sum`; сборка из `$GITHUB_ACTION_PATH`: `CGO_ENABLED=0 GOFLAGS=-mod=readonly go build -trimpath -o "$RUNNER_TEMP/gatekeeper" ./cmd/gatekeeper`. Выход `gatekeeper` — путь к бинарнику. Длительность сборки в секундах — в `$GITHUB_STEP_SUMMARY` строкой `gatekeeper build: N s` (исходные данные для порога ADR 0003).
- **`scan`:** `chmod +x` бинарника (артефакты не сохраняют бит исполнения), `gatekeeper scan --source … --out "$RUNNER_TEMP/result.json"` с `set +e`; выходы `result` и `code`. Action **не падает** при находках: решение принимает шаблон после выгрузки результата.
- **`target`:** `chmod +x`, `gatekeeper evidence-target --repo "$GITHUB_REPOSITORY" --config …` → выходы `branch`, `origin`.
- **`record`:** `chmod +x`; пустой `GATEKEEPER_SIGNING_KEY` → ошибка с понятным текстом (без значения); запуск `"$GITHUB_ACTION_PATH/scripts/evidence-push.sh"` с `GATEKEEPER_BIN`, `RESULT_FILE`, `EVIDENCE_DIR`, `EVIDENCE_BRANCH` (из `evidence-target`, вычисляется внутри шага), `REPO`, `COMMIT`, `RUN_URL`, `RUN_ID`, `RUN_ATTEMPT` из контекста через `env`.

## 2. Dogfooding: `.github/workflows/gatekeeper.yml`
Перевести на `uses: ./` строго по шаблону ADR 0003:
- `scan`: checkout → `./` `mode: build` → `./` `mode: scan` → `upload-artifact` (бинарник и `result.json` одним артефактом) → шаг, падающий при `code != 0`.
- `record`: условия и права как сейчас; checkout кода → `download-artifact` → `./` `mode: target` → `actions/checkout` ветки журнала (`ref` из `target`, `path: evidence`, `persist-credentials: true`, `fetch-depth: 0`) → `./` `mode: record` с `GATEKEEPER_SIGNING_KEY` в `env` **только этого шага**.
- Самотесты `evidence-push.sh` и `rotation_test.sh` не трогать.

## 3. Самотест action на PR (без секретов)
Новое задание `action self-test`: `./` `mode: build` → `./` `mode: scan` на временном каталоге с тестовым токеном, собранным в рантайме (ожидается `code == 1`), и на чистом каталоге (`code == 0`) → `./` `mode: target` (проверка `branch`/`origin` для эпохи 1) → `./` `mode: record` против локального bare-репозитория с ключом, созданным в задании (`openssl genpkey -algorithm ed25519`), затем `trustcore verify` журнала. Ключ живёт только в каталоге задания.

## 4. Шаблон для клиента
`examples/client-workflow.yml` — готовый к копированию workflow по ADR 0003 с `uses: XtReL/devsecops-gatekeeper@<FULL_SHA>` и комментариями к каждому шагу; оба задания на `ubuntu-latest`. `scripts/lint-workflows.sh` проверяет и `examples/*.yml` (запрещённые триггеры).

## 5. Документация
- `docs/onboarding.md`: ключ на устройстве владельца, environment `gatekeeper-evidence` (развёртывание только из ветки по умолчанию), `gh secret set` из stdin, `gatekeeper evidence-init` и сиротская ветка, ruleset для веток журнала, шаблон workflow, `.gatekeeper/evidence.json`, первая проверка `trustcore verify` и `.gatekeeper/evidence.pub`.
- `docs/adr/0001-action-evidence.md`: в чек-листе задания `record` — ссылка на расширенный чек-лист ADR 0003.
- `CLAUDE.md`: правило «входы action и контекст GitHub — только через `env`, никогда `${{ }}` внутри `run:`».
- `README`: раздел «Подключение» — ссылка на `docs/onboarding.md` и шаблон.

## Проверка перед push
`scripts/check.sh` → `check: OK`; gitleaks-самоскан чистый; в PR — полный вывод и длительность `build` из самотеста.
