# RECHECK-1 — независимая проверка

Объект: до = `7e2f7b63fa71b4a9f3cb2a8c471a52119d7273f5`, после = `f7c2cfe1f5c4d63c295d2bb8647faa4f276f160a`.
Код не менялся. `docs/acceptance/*.md` не открывались (см. `OPENED-FILES.txt`).
Проверки Q1–Q5 исполняют настоящие шаги `run:` из `action.yml` проверяемого коммита
(Resolve evidence target, Record evidence) и бинарник `gatekeeper`, собранный из этого коммита.
Ожидания записаны в самих скриптах до первого запуска; расхождение даёт код 1.

| # | Вопрос | До (7e2f7b6) | После (f7c2cfe) |
|---|--------|--------------|-----------------|
| 1 | config из action.yml доходит до record? | **Нет.** В шаге record `CONFIG` идёт только в `evidence-target` (вычисление ветки). `evidence-push.sh` не передаёт `--config`, `gatekeeper record` читает конфиг по умолчанию (эпоха 1). С конфигом эпохи 2 шаг падает: `current checkpoint does not verify under this log key`, записей 0. В режиме target вход доходит. | **Да.** `EVIDENCE_CONFIG` → `evidence-push.sh` → `--config`. Запись ушла в журнал эпохи 2 (ветка `gatekeeper-evidence-e2`), записей 1. |
| 2 | Второй JSON-объект после первого | Молча игнорируется: exit 0, `branch=gatekeeper-evidence-e2` (по первому объекту). | exit 2: `unexpected data after the JSON object`, вывода `branch`/`origin` нет. Один объект + перевод строки по-прежнему принимается. |
| 3 | config не задан, файла нет | Эпоха 1: `branch=gatekeeper-evidence`, record пишет запись. (Вход не задан → default `.gatekeeper/evidence.json`, файла нет → эпоха 1.) | То же: эпоха 1, record пишет запись. (default `''`, флаг `--config` не передаётся.) |
| 4 | Явно `.gatekeeper/evidence.json`, файла нет | Молча эпоха 1: target exit 0, record пишет запись. | Ошибка: exit 2, `read config … no such file or directory`; record не пишет (записей 0). |
| 5 | Явно пустой `--config` | Принимается как «не передан»: exit 0, эпоха 1; `record --config ""` тоже успешен (запись добавлена). Обе формы: `--config ""` и `--config=`. | exit 2: `--config is empty (omit the flag to use .gatekeeper/evidence.json)`, для `evidence-target` и `record`; запись не добавляется. |

Оговорки:
- Q5 проверен на уровне бинарника. Как раннер GitHub трактует явный `config: ''` у входа с default, я не проверял (раннера нет). В `after` action опускает `--config` при пустом входе, `before` передаёт `--config "$CONFIG"` как есть; случай `CONFIG=""` для шага target покрыт G1 из C23 (оба коммита: exit 0, эпоха 1).
- Q1 в `before`: что будет, если в cwd шага record случайно лежит `.gatekeeper/evidence.json` с той же эпохой, не проверялось (по коду record прочтёт его, не `CONFIG`).

## Скрипты приёмки

| Файл | sha256 по SHA256SUMS | Запуск |
|------|----------------------|--------|
| C23/c23-config-strict-repro.sh | совпал | `before`/`defect`: 18 случаев, расхождений 0. `after`/`fixed`: 18 случаев, расхождений 0. Контроль «не тот режим» даёт exit 1 в обоих (`c23-negctl-*.log`). |
| C24/c24-recheck-assert.sh | совпал | **Не запускался** (см. ниже). |
| C24/c24-config-input-control.sh | **записи в SHA256SUMS нет** | **Не запускался.** |

C24: обёртка `c24-recheck-assert.sh` при запуске исполняет `c24-config-input-control.sh`, а у него в `SHA256SUMS` нет строки. Условие «сверить sha256 до запуска» для него выполнить нельзя, поэтому C24 пропущен (`runs/c24-NOT-RUN.txt`). Нужно решение владельца: добавить хеш в `SHA256SUMS` на ветке приёмки или явно разрешить запуск.

## Прочее
- `scripts/check.sh` остановился на шаге `gosec`: `go run …/gosec@v2.29.0` требует модуль вне `go.sum`, а сеть разрешена только для модулей по `go.sum` (запуск с `GOPROXY=off`). До этого шага `gofmt`, `go vet`, `go test -race` и сборка прошли; шаги после gosec (lint-workflows, self-scan, evidence-push_test, rotation_test) не выполнялись. Код объекта проверки не менялся, поэтому, по решению владельца, на выводы проверки это не влияет. Правило CLAUDE.md о зелёном `check.sh` перед push для этой работы владелец не применил (в коммите только файлы `approval/RECHECK-1/`, кода нет). Лог приложен как есть: `runs/check-sh.log`.
- Go скачал toolchain `go1.25.8` (по `toolchain`/`go` в go.mod) при первом вызове `go`; это загрузка с `proxy.golang.org` под проверкой sumdb, а не запись из `go.sum` репозитория.
- Для воспроизведения: `run-checks.sh <before-tree> <before-bin> <after-tree> <after-bin> <runs-dir>`.

## Состав папки
- `checks/` — lib.sh и q1…q5; `run-checks.sh`
- `runs/` — полный вывод каждого прогона отдельным файлом: `q{1..5}-{before,after}.log`, `negctl-q*.log` (контроль «ожидания не того коммита»; для Q3 поведение совпадает, оба exit 0), `c23-*.log`, `sha256-verify.log`, `check-sh.log`, `c24-NOT-RUN.txt`
- `SHA256SUMS` — дословная копия из `origin/acceptance/act-v0`; `SHA256SUMS.outputs` — sha256 файлов этой папки
