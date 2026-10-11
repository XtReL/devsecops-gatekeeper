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

| Файл | sha256 | Запуск |
|------|--------|--------|
| C23/c23-config-strict-repro.sh | совпал с `SHA256SUMS` | `before`/`defect`: 18 случаев, расхождений 0. `after`/`fixed`: 18 случаев, расхождений 0. Контроль «не тот режим» даёт exit 1 в обоих (`c23-negctl-*.log`). |
| C24/c24-recheck-assert.sh | совпал с `SHA256SUMS` | Раунд 2, см. ниже. |
| C24/c24-config-input-control.sh | в `SHA256SUMS` записи нет; **совпал со значением владельца** `b41b6e70…2feb` (источник по словам владельца: `ACT-0.1-RECHECK-1.sha256`, этот файл я не открывал) | Раунд 2, см. ниже. |

В раунде 1 C24 не запускался именно из-за отсутствия хеша; в раунде 2 владелец сообщил ожидаемый хеш, сверка прошла (`runs/sha256-verify-round2.log`).
Ветку `acceptance/act-v0` и её `SHA256SUMS` я не менял (`SHA256SUMS` в ветке побайтно равен копии здесь; ветка на `49552f1`).
Зависимость: контроль копирует `custom.json` из своего каталога. Его хеша нет ни в `SHA256SUMS`, ни у владельца; это данные (13 байт, `{"epoch": 2}`), sha256 `b910fa1a…b8e1` записан в `runs/sha256-verify-round2.log`. Запускался без проверки этого хеша.

### C24, раунд 2 (дерево и бинарник одного и того же коммита)

| Запуск | exit | Что видно |
|--------|------|-----------|
| контроль, до | 0 | случай 1: `record step exit=1` (`current checkpoint does not verify under this log key`); случай 2: `exit=0` |
| контроль, после | 0 | случай 1: `exit=0` (запись добавлена); случай 2: `exit=0` (`already recorded`) |
| обёртка, до, `defect` | **0** | `ASSERT OK` |
| обёртка, до, `fixed` | 1 | `ASSERT FAIL: случай 1: код 1, ожидался 0` |
| обёртка, после, `defect` | 1 | `ASSERT FAIL: случай 1: код 0, ожидался 1` и нет сообщения об отказе |
| обёртка, после, `fixed` | **0** | `ASSERT OK` |

Естественные пары (до/`defect`, после/`fixed`) проходят, перекрёстные падают, то есть утверждения обёртки различают коммиты. Выводы по Q1 подтверждаются независимым контролем: до исправления config доходит только до выбора ветки, а `record` читает путь по умолчанию.
Случай 2 «до» проходит потому, что конфиг положен ещё и в `.gatekeeper/evidence.json`, который `record` читает сам, а не из входа `config` (это закрывает оговорку про Q1 из раунда 1). Случай 2 «после» идёт после случая 1 с теми же `run-id` и даёт `already recorded`, независимой информации не несёт (так сказано и в самой обёртке).
«Перекрёстные пары» понимаю как режим × коммит; смешанные пары (бинарник одного коммита, дерево другого) не запускались.

## Прочее
- `scripts/check.sh` остановился на шаге `gosec`: `go run …/gosec@v2.29.0` требует модуль вне `go.sum`, а сеть разрешена только для модулей по `go.sum` (запуск с `GOPROXY=off`). До этого шага `gofmt`, `go vet`, `go test -race` и сборка прошли; шаги после gosec (lint-workflows, self-scan, evidence-push_test, rotation_test) не выполнялись. Код объекта проверки не менялся, поэтому, по решению владельца, на выводы проверки это не влияет. Правило CLAUDE.md о зелёном `check.sh` перед push для этой работы владелец не применил (в коммите только файлы `approval/RECHECK-1/`, кода нет). Лог приложен как есть: `runs/check-sh.log`.
- Go скачал toolchain `go1.25.8` (по `toolchain`/`go` в go.mod) при первом вызове `go`; это загрузка с `proxy.golang.org` под проверкой sumdb, а не запись из `go.sum` репозитория.
- Для воспроизведения: `run-checks.sh <before-tree> <before-bin> <after-tree> <after-bin> <runs-dir>`.

## Состав папки
- `checks/` — lib.sh и q1…q5; `run-checks.sh`
- `runs/` — полный вывод каждого прогона отдельным файлом: `q{1..5}-{before,after}.log`, `negctl-q*.log` (контроль «ожидания не того коммита»; для Q3 поведение совпадает, оба exit 0), `c23-*.log`, `c24-control-*.log`, `c24-assert-*-mode-*.log`, `c24-exit-codes.log`, `sha256-verify.log`, `sha256-verify-round2.log`, `check-sh.log`
- `SHA256SUMS` — дословная копия из `origin/acceptance/act-v0`; `SHA256SUMS.outputs` — sha256 файлов этой папки
