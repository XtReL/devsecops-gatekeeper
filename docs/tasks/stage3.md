# TASK: этап 3 — Gatekeeper Action пишет подписанные аттестации

Архитектура зафиксирована в `docs/adr/0001-action-evidence.md`. **Прочитай ADR до начала работы.** Если реализация требует отступить от ADR, остановись и спроси, не меняй решение сам.

## Общие правила

- Каждая фаза — отдельная ветка и отдельный PR. PR не сливать: это делает человек после зелёного CI.
- `main` защищён ruleset: прямой push в `main` запрещён.
- Все GitHub Actions закрепляются на полных SHA коммитов, тег — в комментарии.
- **В исходниках и тестовых данных не должно быть строк, похожих на секреты.** Тестовые «секреты» собираются во время выполнения из частей, а не пишутся литералом. Тело — не повторяющийся паттерн (`strings.Repeat("a1", 18)` даёт entropy 1.0 и не проходит порог entropy >= 3 правила gitleaks `github-pat`, поэтому сканер его просто не находит — проверено фактическим прогоном сканера), а строка с реальной энтропией: например SHA-256 фиксированной строки (`"gh" + "p_" + sha256("label")[:36]`, entropy ~3.6) или детерминированный PRNG по алфавиту из разных символов. Иначе сработают gitleaks и GitGuardian на самом репозитории.
- Ключи (`*.key`) никогда не коммитятся и не пишутся на диск в CI.
- После каждой фазы: `gofmt -l .` пусто, `go vet ./...` чисто, `go test ./...` зелёный.

---

## Фаза 1. Trust Core: разбор ключей из памяти, релиз v0.1.0

Репозиторий: `X:\pars\trust-core`. Запускай Claude Code **из этой папки**.

1. В `keys/keys.go` добавить:
   - `func ParseSigner(pemBytes []byte) (*Signer, error)`
   - `func ParsePublic(pemBytes []byte) (ed25519.PublicKey, error)`

   `LoadSigner` и `LoadPublic` переписать через них: чтение файла + вызов Parse*.
2. Тесты в `keys/keys_test.go`: генерация → PEM → Parse* → подпись и проверка; отказ для PEM не того типа; отказ для мусора.
3. Ветка `feat/parse-keys`, PR, после слияния человек ставит тег:
   ```bash
   git switch main && git pull
   git tag -a v0.1.0 -m "Trust Core v0.1.0"
   git push origin v0.1.0
   ```

**Проверка фазы:** CI `test` и `interop` зелёные; `git ls-remote --tags origin` показывает `v0.1.0`.

---

## Фаза 2. Движок сканирования и `gatekeeper scan`

Репозиторий: `X:\pars\devsecops-gatekeeper`. Ветка `feat/engine`.

### Зависимости
- `github.com/zricethezav/gitleaks/v8 v8.30.1` — как **библиотека**, без запуска бинарника.
- `github.com/XtReL/trust-core v0.1.0`.

API gitleaks сверь по исходникам модуля в кэше Go (`go env GOMODCACHE`). Ориентиры: `detect.NewDetectorDefaultConfig()`, `(*Detector).DetectSource(ctx, sources.Source)`, `sources.Files`, встроенные правила — `config.DefaultConfig`, SARIF — репортер в пакете `report`.

### `internal/engine`
```go
type Finding struct {
    RuleID      string `json:"rule"`
    File        string `json:"file"`        // путь относительно корня, разделитель "/"
    Fingerprint string `json:"fingerprint"` // "sha256:" + hex(sha256(secret))
}
type Result struct {
    Format          string    `json:"format"`          // "gatekeeper-scan/v1"
    GitleaksVersion string    `json:"gitleaksVersion"` // из runtime/debug.ReadBuildInfo
    RulesDigest     string    `json:"rulesDigest"`     // "sha256:" + hex(sha256(config.DefaultConfig))
    Findings        []Finding `json:"findings"`        // пустой массив, а не null
}
func Scan(ctx context.Context, dir string) (Result, error)
```
Требования к детерминизму:
- каталог `.git` не сканируется;
- находки отсортированы по (File, RuleID, Fingerprint), одинаковые тройки схлопнуты;
- в результате нет времени, абсолютных путей, номеров строк, значений секретов и их фрагментов;
- JSON: `json.MarshalIndent(result, "", "  ")` плюс перевод строки в конце.

### `cmd/gatekeeper`
- `gatekeeper scan --source DIR --out FILE [--sarif FILE]` — коды выхода: `0` чисто, `1` есть находки, `2` ошибка.
- `gatekeeper version`.

### Тесты
- Детерминизм: временный каталог с двумя файлами, содержащими собранные в рантайме тестовые токены. Два прогона дают побайтно одинаковый `result.json`. Создание файлов в обратном порядке — тот же результат.
- Чистый каталог → `findings: []`, код выхода 0.
- Каталог `.git` с «секретом» внутри игнорируется.
- Отдельная проверка: в выводе нет значения тестового секрета.

### Проверка в CI
Шаг в существующий `ci.yml`: сбой, если в `.github/workflows/` есть `workflow_run` или `pull_request_target`.

**Проверка фазы:** `go test ./...` зелёный; `go run ./cmd/gatekeeper scan --source . --out /tmp/r1.json` дважды → `cmp` без различий; код выхода 0 на самом репозитории.

---

## Фаза 3. `gatekeeper record`, `evidence-init` и workflow

Ветка `feat/record`.

### Команды
- `gatekeeper evidence-init --evidence DIR --repo OWNER/REPO --key FILE` — локально, один раз: `filelog.Init` с origin `github.com/OWNER/REPO/gatekeeper-evidence/v1` **и создание `entries/.gitkeep`** (git не хранит пустые каталоги; без него в CI не будет `entries/`). Для этого репозитория ветка уже инициализирована через `trustcore init` (формат тот же); команда нужна клиентам.
  - `record` и `verify` должны игнорировать `entries/.gitkeep` (в trust-core `CountEntryFiles` и `LeafHashes` смотрят только на нумерованные файлы — добавь тест, подтверждающий это).
- `gatekeeper record --result FILE --evidence DIR --repo OWNER/REPO --commit SHA --run-url URL --run-id ID --run-attempt N`
  - ключ — только из переменной окружения `GATEKEEPER_SIGNING_KEY` через `keys.ParseSigner`;
  - строит `event.NewTestResult`:
    - subject: `git+https://github.com/OWNER/REPO`, `gitCommit: SHA`;
    - `result`: `PASSED`, если находок нет, иначе `FAILED`; `failedTests` — отсортированные уникальные `RuleID`;
    - `configuration[0]`: `name: "gatekeeper-scan-result"`, `digest.sha256` = sha256 файла `result.json`, аннотации: `format`, `gitleaksVersion`, `rulesDigest`, `gatekeeperVersion`, `findings` (массив из result), `run_id`, `run_attempt`, `reproduce: "git checkout SHA && gatekeeper scan --source . --out result.json"`;
    - `url`: ссылка на запуск;
  - идемпотентность: если в журнале уже есть запись с теми же `run_id` и `run_attempt` — ничего не добавлять, код выхода `3`;
  - коды выхода: `0` добавлено, `3` уже было, `2` ошибка.

### `scripts/evidence-push.sh`
Оптимистичная запись без `concurrency` (ADR, поправки 2 и 3). До 5 попыток:
```
git -C evidence fetch origin gatekeeper-evidence
git -C evidence reset --hard origin/gatekeeper-evidence
gatekeeper record ...        # код 3 → успех, выход 0
git -C evidence add -A && git -C evidence commit -m "evidence: <sha> run <id>/<attempt>"
git -C evidence push origin HEAD:gatekeeper-evidence && выход 0
пауза: attempt*attempt*2 + RANDOM%5 секунд
```
После 5 неудач — выход 1. Никакого `git rebase`. После успеха — содержимое `evidence/checkpoint` в `$GITHUB_STEP_SUMMARY`.

### `.github/workflows/gatekeeper.yml`
```yaml
on:
  pull_request:
  push:
    branches: [main]
permissions:
  contents: read
```
**Задание `scan`** (без секретов, без environment):
- checkout (`persist-credentials: false`), setup-go (`go-version-file: go.mod`);
- `GOFLAGS=-mod=readonly go build -o "$RUNNER_TEMP/gatekeeper" ./cmd/gatekeeper`;
- скан с `set +e`, код выхода → output `code`;
- `upload-artifact` `result.json` с `if: always()`;
- затем шаг, который падает, если `code != 0`.

**Задание `record`:**
- `needs: scan`;
- `if: always() && (needs.scan.outputs.code == '0' || needs.scan.outputs.code == '1') && github.event_name == 'push' && github.ref == format('refs/heads/{0}', github.event.repository.default_branch)` — FAILED-результаты тоже записываются;
- `environment: gatekeeper-evidence`, `permissions: contents: write`;
- шаги только из чек-листа ADR: checkout кода (`persist-credentials: false`), setup-go, сборка, `download-artifact`, checkout ветки `gatekeeper-evidence` в `path: evidence` с `persist-credentials: true` и `fetch-depth: 0`, затем `scripts/evidence-push.sh` с `GATEKEEPER_SIGNING_KEY: ${{ secrets.GATEKEEPER_SIGNING_KEY }}`.

### Тесты
- `record` на временном журнале: два вызова с одним `run_id`/`run_attempt` → одна запись; другой `run_id` → две; `verify.Log` из trust-core проходит.
- Запись с `FAILED`: `failedTests` отсортирован, в аттестации нет значений секретов.

**Проверка фазы:** тесты зелёные; `gatekeeper.yml` проходит на PR (scan зелёный, record пропущен).

---

## Фаза 4. Ручная настройка — ✅ выполнено (26.09.2026, Termux)

- Ключ создан на устройстве владельца (`trustcore keygen`), приватный ключ не покидал устройство.
- Environment `gatekeeper-evidence` (deployment branch: `main`), секрет `GATEKEEPER_SIGNING_KEY` загружен через `gh secret set` из stdin.
- Ветка `gatekeeper-evidence`: корневой коммит `c5205ec`, `checkpoint` (size 0) + `entries/.gitkeep`; подпись проверена опубликованным ключом.
- Публичный ключ: `.gatekeeper/evidence.pub` (PR #31).
- Ruleset `evidence-protection` для `gatekeeper-evidence`: Restrict deletions + Block force pushes, без требования PR и проверок.
- ⬜ Эмпирический тест безопасности — после фазы 3: PR с тестовым workflow, где задание с `environment: gatekeeper-evidence` печатает длину секрета. Ожидается отказ «Branch … is not allowed to deploy to gatekeeper-evidence». PR закрыть без слияния.

## Приёмка этапа 3

1. После слияния фазы 3 в `main`: запуск push — `scan` зелёный, `record` зелёный, в `gatekeeper-evidence` появилась запись.
2. Независимая проверка журнала:
   ```bash
   git clone --branch gatekeeper-evidence --single-branch https://github.com/XtReL/devsecops-gatekeeper.git ev
   trustcore verify -log ev -origin github.com/XtReL/devsecops-gatekeeper/gatekeeper-evidence/v1 -log-pub .gatekeeper/evidence.pub -attester-pub .gatekeeper/evidence.pub
   ```
3. Воспроизводимость: checkout записанного коммита → `gatekeeper scan` → sha256 `result.json` равен `digest.sha256` в аттестации.
4. Тест безопасности из фазы 4 дал отказ.
