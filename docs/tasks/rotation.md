# TASK: Gatekeeper — эпохи журнала и ротация ключа (ADR 0002)

Прочитай `CLAUDE.md`, `docs/adr/0001-action-evidence.md` и ADR 0002 в trust-core (`github.com/XtReL/trust-core/blob/main/docs/adr/0002-key-rotation.md`). Решения ADR не меняй; при неясности — остановись и спроси. Один PR в `main`, не сливать.

## Цель
Сейчас ветка журнала (`gatekeeper-evidence`) и origin (`…/gatekeeper-evidence/v1`) зашиты в код, скрипт и workflow. После ротации запись должна идти в новую эпоху без правки кода — только сменой номера эпохи в конфиге.

## 1. Зависимость
`github.com/XtReL/trust-core` → `v0.2.0` (`event.EpochOrigin`, `event.ParseEpoch`).

## 2. Конфиг эпохи — единственный источник
- Файл `.gatekeeper/evidence.json` в ветке по умолчанию: `{"epoch": 1}`. Больше полей нет: ветка и origin **выводятся** из номера эпохи, дублей быть не должно.
- Файла нет → эпоха 1 (обратная совместимость).
- Правила вывода:
  - origin = `event.EpochOrigin(evidence.Origin(repo), epoch)`: эпоха 1 → `github.com/OWNER/REPO/gatekeeper-evidence/v1`, эпоха k ≥ 2 → `…/v1/e<k>`;
  - ветка = `gatekeeper-evidence` для эпохи 1, `gatekeeper-evidence-e<k>` для k ≥ 2.
- `internal/evidence`: `LoadConfig(path)` (строгий JSON, неизвестные поля — ошибка, epoch ≥ 1), `Target(repo, cfg) (branch, origin string)`.

## 3. CLI
- `gatekeeper evidence-target --repo OWNER/REPO [--config .gatekeeper/evidence.json]` печатает две строки `branch=…` и `origin=…` — формат, пригодный для `$GITHUB_OUTPUT`.
- `gatekeeper record`: новый флаг `--config` (по умолчанию `.gatekeeper/evidence.json`); `filelog.Open` — с origin из `Target`. Остальное поведение `record` не меняется.
- `gatekeeper evidence-init`: флаг `--epoch` (по умолчанию 1) — для клиентов, начинающих не с первой эпохи; для эпох ≥ 2 журнал создаёт `trustcore rotate`, а не `evidence-init`.

## 4. Скрипт и workflow
- `scripts/evidence-push.sh`: ветка берётся из переменной `EVIDENCE_BRANCH` (обязательна; пустая — ошибка). Все `fetch`, `reset`, `push` — в эту ветку. Логика повторов не меняется.
- `.github/workflows/gatekeeper.yml`, задание `record`:
  - после сборки — шаг `gatekeeper evidence-target` → выходы `branch`, `origin`;
  - checkout журнала — `ref: ${{ steps.<id>.outputs.branch }}`;
  - `EVIDENCE_BRANCH` для скрипта — из того же выхода;
  - новых actions не добавлять; чек-лист задания `record` из ADR 0001 остаётся в силе.

## 5. Документация
- `docs/runbooks/key-rotation.md` — процедура по ADR 0002 для обоих видов ротации: команды `trustcore keygen`, `trustcore rotate`, создание сиротской ветки `gatekeeper-evidence-e<k>` из каталога новой эпохи, push, `gh secret set GATEKEEPER_SIGNING_KEY` из stdin, PR с `.gatekeeper/evidence.json` и `.gatekeeper/keys/e<k>.pub`, пример манифеста проверяющего и `trustcore verify-chain`. Отдельно для `unplanned`: доверенный чекпоинт, уведомление проверяющих вне журнала (новый origin, keyid, причина, дата; GitHub Security Advisory). Для `planned`: уничтожить старый приватный ключ после ротации.
- Ruleset: в runbook — две явные цели `gatekeeper-evidence` и `gatekeeper-evidence-e*` (настраивает человек).
- `docs/adr/0001-action-evidence.md`: строку «Ротация — добавлением нового ключа: верификатор принимает несколько» заменить на ссылку на ADR 0002 (ротация эпохами).
- `.gatekeeper/evidence.json` с `{"epoch": 1}` — добавить в этом же PR.

## 6. Самотест ротации в CI
`scripts/rotation_test.sh` (изолированный git, как `evidence-push_test.sh`; ключи создаются в тесте и не коммитятся; `trustcore` собирается из версии в `go.mod`):
1. эпоха 1: init, две записи через `evidence-push.sh`;
2. **planned:** `trustcore rotate` с обоими ключами → новая сиротская ветка `gatekeeper-evidence-e2` в bare-репозитории; конфиг `{"epoch": 2}`; запись через `evidence-push.sh` уходит в `e2`, а ветка `gatekeeper-evidence` не меняется; `trustcore verify-chain` по манифесту → OK;
3. **unplanned:** из той же исходной эпохи 1 — `trustcore rotate` без старого ключа с доверенным чекпоинтом; `verify-chain` без `acceptUnplanned` → код 1; с верным keyid → код 0;
4. в конце — строка `rotation_test: OK`.

Добавь `scripts/rotation_test.sh` в `scripts/check.sh` и отдельным заданием без секретов в workflow `Gatekeeper Action` (по образцу `evidence-push.sh self-test`).

## 7. Тесты Go
- `LoadConfig`: отсутствие файла → эпоха 1; неизвестное поле, `epoch: 0`, мусор → ошибка.
- `Target`: эпохи 1, 2, 10 — точные ветка и origin.
- `record` с конфигом эпохи 2 пишет в журнал с origin `…/v1/e2`.

## Проверка перед push
`scripts/check.sh` → `check: OK`, полный вывод. gitleaks-самоскан чистый.
