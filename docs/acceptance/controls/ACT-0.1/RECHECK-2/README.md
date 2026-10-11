# Контроли и выводы прогонов ACT-0.1-RECHECK-2

Протокол: `docs/acceptance/ACT-0.1-RECHECK-2.md`. Объект: `ba73ba0b78ec91a4ac66bdd9ec9956ea8eee87c0` (ветка `fix/act-0.1`), база: `f7c2cfe1f5c4d63c295d2bb8647faa4f276f160a`.
Хэши всех файлов этой папки, протокола и использованных контролей RECHECK-1 — в одном манифесте `docs/acceptance/ACT-0.1-RECHECK-2.sha256` (`cd docs/acceptance && sha256sum -c ACT-0.1-RECHECK-2.sha256`). Отдельного `SHA256SUMS` здесь нет.

Каждый файл `NN-*.log` — полный вывод одного прогона: шапка (`date-utc`, `cwd`, `cmd`), вывод команды (stdout и stderr), `exit` и `end-utc`. Пути `/tmp/claude-0/.../scratchpad/...` — временные каталоги сессии, их нет в репозитории. Единственное изменение выводов после прогона: в `08-pre-check-sh-object.log` (строки 261, 287) и `51-p5-check-sh-test-branch.log` (строки 215, 241) значение `key id` (идентификатор публичного ключа, созданного внутри `rotation_test.sh`) заменено на длину и энтропию — иначе самоскан `check.sh` находит `generic-api-key` (методика 6.4, CLAUDE.md). Остальное не правилось.

## Подготовка

```bash
S=$(mktemp -d)
git archive ba73ba0 | (mkdir -p $S/ba73ba0 && tar -x -C $S/ba73ba0)
git archive 7e2f7b6 | (mkdir -p $S/7e2f7b6 && tar -x -C $S/7e2f7b6)
(cd $S/ba73ba0 && GOFLAGS=-mod=readonly go build -o bin/gatekeeper ./cmd/gatekeeper)
R=docs/acceptance/controls/ACT-0.1/RECHECK-2
```

Нужны `go 1.25.8`, `patch`, `python3` с `yaml`, `openssl`, `git`.

## Контроли

| Контроль | Строка протокола | Куда положить | Команда | Ожидание |
|---|---|---|---|---|
| `../RECHECK-1-mutations/K8.patch` (без изменений) | Т1 | применяется к копии объекта | `cd <копия> && patch -p1 < .../K8.patch && go test -count=1 -v -run '^TestRunRecordRejectsEmptyConfigFlag$' ./cmd/gatekeeper` | код 1, `config_test.go:141: record --config "": expected exit 2 ...`, ошибок сборки нет |
| откат `internal/evidence/evidence.go` и `cmd/gatekeeper/main.go` к `7e2f7b6` | Т2 | копия объекта, два файла заменены файлами `7e2f7b6` | `go test -count=1 -v -run '^TestRunRecordAppliesCustomConfig$' ./cmd/gatekeeper`; `go test -count=1 -v -run '^TestRecordRejectsMissingNamedConfig$' ./internal/evidence` | оба код 1: `main_test.go:306 ... failed for the wrong reason ... does not verify`; `evidence_test.go:664 Record succeeded with a missing named config` |
| `p5-test-branch/recheck-2-config.yml.txt`, `EXPECTATIONS.md`, `epoch2.json` | Т5 | копии файлов коммита `363a6680` ветки `test/recheck-2-config` (workflow хранится с `.txt`, чтобы не попасть в `.github/workflows`) | push в `test/recheck-2-config` | все 5 заданий `success`, ожидания — `EXPECTATIONS.md` |
| `p5-extract-mcp-logs.py` | Т5 | никуда | `python3 -I p5-extract-mcp-logs.py <session.jsonl> 38162383246 p5-run-38162383246/run-38162383246-jobs.json p5-run-38162383246` | 5 строк `ok`, число строк = `original_length` |
| `p5-assert.sh` | Т5 | никуда | `bash p5-assert.sh p5-run-38162383246 38162383246` | `p5: OK` (40 проверок); на подделанной копии — `p5: FAIL` |
| `../C23/c23-config-strict-repro.sh` (без изменений) | Т6 | никуда | `bash ../C23/c23-config-strict-repro.sh $S/ba73ba0/bin/gatekeeper $S/ba73ba0 fixed` | код 0, 0 из 18 расхождений; `defect` — код 1, 12 из 18 |
| `../C24/c24-recheck-assert.sh` (без изменений) | Т6 | никуда | `bash ../C24/c24-recheck-assert.sh $S/ba73ba0/bin/gatekeeper $S/ba73ba0 fixed` | код 0, `ASSERT OK`; `defect` — код 1 |
| `run-recheck-2.sh` | Т1, Т2, Т5, Т6 | никуда | `bash $R/run-recheck-2.sh $S/ba73ba0 $S/7e2f7b6`; `bash $R/run-recheck-2.sh --verify` | `run-recheck-2: OK`; `run-recheck-2: manifest OK` |

## Файлы прогонов

| Файлы | Что |
|---|---|
| `01`–`08` | Предпроверка (раздел 10): `git status`, `go vet`, `go test -count=1` дважды, состав тестов, `-v` по изменённым тестам, `check.sh` на объекте |
| `10`–`14`, `13-K8-layer-logs/`, `14-K1-K9-layer-logs/` | Т1: применение K8, падение теста (2 прогона), слой GO, `run-mutations.sh K8`; дополнительно K1-K9 на объекте |
| `20`–`26` | Т2: дифф отката, прогоны (2 повтора), контраст со старыми тестами, раздельные откаты, K6 |
| `30` | Т3: строки `docs/tasks`, `action.yml`, `LoadConfig` |
| `40`–`42` | Т4 и шапка: ссылка README, подписи коммитов и видимость через API |
| `50`–`52`, `70`–`74`, `p5-run-38162383246/` | Т5: проверка триггеров до push, `check.sh` на тестовой ветке, push, извлечение логов, проверка, подделанная копия, ветка `gatekeeper-evidence`, предупреждение кэша `setup-go` на `main` |
| `60`–`64` | Т6: C23 и C24 на объекте (fixed дважды, defect), C23 на `f7c2cfe` для сравнения |
| `80` | `run-recheck-2.sh` на свежих деревьях |

`p5-run-38162383246/`: `run-*.json`, `run-*-jobs.json`, `run-*-artifacts.json`, `job-*-annotations.json`, `runs-for-*.json` — ответы GitHub REST API, сохранённые `curl` без изменений; `run-*-job-*.log` — логи заданий, полученные через GitHub MCP `get_job_logs` и извлечённые `p5-extract-mcp-logs.py` из журнала сессии (прямая загрузка `/actions/jobs/<id>/logs` упирается в запрет egress-прокси на хранилище логов).
