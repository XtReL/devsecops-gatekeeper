# Исходники контролей к акту ACT-0.1

Здесь лежат исходники положительных контролей из акта `docs/acceptance/ACT-0.1.md`. Они были в рабочем каталоге сессии акта (scratchpad). Контейнер сессии временный, поэтому файлы перенесены в репозиторий.

Файлы Go лежат с добавочным расширением `.txt`. Так `go test ./...`, `go vet` и `gosec` их не собирают. Перед запуском файл нужно положить во временную копию и убрать `.txt`.

## Проверка при сохранении (REV-2, 2026-10-10)

Все контроли из этой папки запущены из сохранённых копий на свежем архиве `7e2f7b6`. Запуск шёл с `GOPROXY=off`, без сети. Результаты совпали с актом. Отличаются только паузы в C13: они зависят от случайного разброса (см. ниже).

Контроли C13 и C24 в сессии акта выполнялись командами, а не файлами. Их сценарии здесь восстановлены по этим командам. Это не побайтная копия того, что запускалось. Отличия: рабочий каталог создаётся через `mktemp`, а не в scratchpad, и код возврата шага читается явно.

Тесты C36, C37 и `extra-repo-name` только пишут результат в лог (`t.Logf`). Они ничего не утверждают и не падают. Результат нужно читать из вывода `go test -v`. Поэтому «PASS» у них ничего не доказывает.

## Подготовка

Нужны `git`, `go` (версия из `go.mod`, 1.25.8), `openssl`, `python3` с модулем `yaml`. Модули Go должны быть в кэше.

```bash
V=$(mktemp -d)                      # временная копия
git archive 7e2f7b6 | tar -x -C "$V"
CTL=<путь к docs/acceptance/controls/ACT-0.1 в этой ветке>
cd "$V"
GOFLAGS=-mod=readonly go build -o bin/gatekeeper ./cmd/gatekeeper
GOFLAGS=-mod=readonly go build -o bin/trustcore github.com/XtReL/trust-core/cmd/trustcore
```

Контроли не меняют рабочее дерево репозитория. Всё делается в `$V` и во временных каталогах.

## C13. Ветка повтора в `scripts/evidence-push.sh`

| | |
|---|---|
| Файлы | `C13/pre-receive` (хук), `C13/c13-retry-control.sh` (сценарий) |
| Куда положить | Ничего не копируется. Сценарий берёт `scripts/evidence-push.sh` из `$V` и сам ставит хук в bare-репозиторий. В хуке путь заменён на `__WORK__`, сценарий подставляет свой каталог. |
| Команда | `bash "$CTL/C13/c13-retry-control.sh" "$V/bin/gatekeeper" "$V/bin/trustcore" "$V"` |
| Время | около 1 минуты (второй случай ждёт все паузы) |

Ожидаемый результат по акту:

- Случай 1 (хук отклоняет первый push): попытка 1 отклонена, попытка 2 успешна, `pipeline exit=0`, `trustcore verify` печатает `OK`.
- Случай 2 (хук отклоняет всегда): 5 попыток, `giving up after 5 attempts`, `pipeline exit=1`.

Паузы между попытками считаются как `попытка*попытка*2 + случайное 0..4` секунд. Допустимые диапазоны: 2-6, 8-12, 18-22, 32-36 секунд. В акте были 6 с (случай 1) и 5/8/22/34 с (случай 2, всего 69 с). При проверке в REV-2: 2 с (случай 1) и 2/10/18/32 с (всего 63 с).

## C24. Вход `config` не доходит до `gatekeeper record`

| | |
|---|---|
| Файлы | `C24/c24-config-input-control.sh` (сценарий), `C24/custom.json` (`{"epoch": 2}`), `C24/record-step.sh` (тело шага `record` из `action.yml`) |
| Куда положить | Ничего не копируется. Сценарий читает `custom.json` из своей папки и заново извлекает тело шага из `$V/action.yml`. |
| Команда | `bash "$CTL/C24/c24-config-input-control.sh" "$V/bin/gatekeeper" "$V"` |

`record-step.sh` сверен с `action.yml` на `7e2f7b6`: файлы совпадают. Получить его заново можно так:

```bash
python3 -I -c 'import sys,yaml;print([s for s in yaml.safe_load(open(sys.argv[1]))["runs"]["steps"] if s.get("id")=="record"][0]["run"])' "$V/action.yml"
```

Ожидаемый результат по акту:

- Случай 1 (конфиг эпохи 2 только по пути `cfg/custom.json`): `record step exit=1`, в выводе `current checkpoint does not verify under this log key`.
- Случай 2 (тот же конфиг ещё и в `.gatekeeper/evidence.json`): `evidence-push: pushed`, `record step exit=0`.

## C26. Проверка значения `mode`

| | |
|---|---|
| Файл | `C26/validate-mode.sh` (шаг `Validate mode` из `action.yml`) |
| Куда положить | Никуда. Запускается из папки контролей. |
| Команда | `for m in build scan target record bogus ""; do MODE="$m" bash -eo pipefail "$CTL/C26/validate-mode.sh" >/dev/null 2>&1; echo "mode='$m' exit=$?"; done` |

Ожидаемый результат по акту: коды `0 0 0 0 1 1`.

Файл совпадает с шагом 0 из `runs.steps` в `action.yml` на `7e2f7b6`. Получить его заново: тот же `python3`, но с `[0]["run"]` вместо выборки по `id`.

## C36. Пустой `STRIPE_WEBHOOK_SECRET` принимает подделку

| | |
|---|---|
| Файл | `C36/acceptance_ctl_test.go.txt` |
| Куда положить | `cp "$CTL/C36/acceptance_ctl_test.go.txt" "$V/internal/billing/acceptance_ctl_test.go"` |
| Команда | `cd "$V" && go test -count=1 -v -run TestCtl ./internal/billing/` |

Ожидаемый результат по акту, читать из лога:

- `server secret EMPTY, attacker signs with empty key -> HTTP 200`
- `server secret SET, attacker signs with empty key -> HTTP 400`

## C37. `parseReport` падает на отчёте без поля `Secret`

| | |
|---|---|
| Файл | `C37/acceptance_ctl_test.go.txt` |
| Куда положить | `cp "$CTL/C37/acceptance_ctl_test.go.txt" "$V/cmd/scanner/acceptance_ctl_test.go"` |
| Команда | `cd "$V" && go test -count=1 -v -run TestCtl ./cmd/scanner/` |

Ожидаемый результат по акту, читать из лога: `recovered panic: interface conversion: interface {} is nil, not string`.

Этот контроль показывает только падение приведения типа. Потеря ошибки gitleaks (код выхода не 0 и не 1 только пишется в лог, задача подтверждается) установлена чтением `cmd/scanner/main.go`, прогона для неё нет.

## Вне заявлений: имена репозиториев

| | |
|---|---|
| Файл | `extra-repo-name/acceptance_ctl_test.go.txt` |
| Куда положить | `cp "$CTL/extra-repo-name/acceptance_ctl_test.go.txt" "$V/internal/middleware/acceptance_ctl_test.go"` |
| Команда | `cd "$V" && go test -count=1 -v -run TestCtl ./internal/middleware/` |

Ожидаемый результат по акту, читать из лога: для `owner/..`, `owner/.`, `-owner/repo`, `owner/.git` везде `err=<nil>`. Контроль относится к находке акта о неверной конфигурации, которая принимается молча. Отдельного номера заявления у него нет.

## Что не сохранено

Следующие проверки выполнялись командами в сессии акта. Файлов с ними здесь нет.

- Команды для C1, C17, C18, C22, C23 уже даны в разделе «Команды для повторения» акта.
- C6, C40: в акте только описание.
- C15 (три неверных ключа), C19 (дубли и порядок), C25 (разбор YAML на `${{ }}`): ни в акте, ни здесь команд нет.
- Три проверки вне заявлений: история git не сканируется, пути из allowlist gitleaks, отпечаток без соли подтверждается подбором.
- Чтение и подсчёты (C2, C7 как поиск литералов, C9, C27 и другие) файлов не имели.

## RECHECK-1 (2026-10-11): контроли повторной приёмки исправлений C23/C24

Добавлено сессией повторной приёмки; контроли выше не менялись. Хэши в `SHA256SUMS` (проверка `sha256sum -c SHA256SUMS` из этой папки), хэш самого `run-recheck-1.sh` приведён в `docs/acceptance/ACT-0.1-RECHECK-1.md`.

Подготовка: деревья `7e2f7b6` и `f7c2cfe` через `git archive`, в каждом `bin/gatekeeper` (`GOFLAGS=-mod=readonly go build -o bin/gatekeeper ./cmd/gatekeeper`) и `trustcore` (`go build github.com/XtReL/trust-core/cmd/trustcore`). Нужны `git`, `go 1.25.8`, `openssl`, `python3` с `yaml`, `patch`.

| Контроль | Строка акта | Куда положить | Команда | Ожидание |
|---|---|---|---|---|
| `C23/c23-config-strict-repro.sh` (репродуктор дефекта) | C23 | никуда, запускается из папки | `bash C23/c23-config-strict-repro.sh <gatekeeper-bin> <root> defect\|fixed` | `7e2f7b6` + `defect`: код 0; `f7c2cfe` + `fixed`: код 0; перекрёстные: код 1 (12 из 18 случаев расходятся, остальные 6 - положительные контроли) |
| `C24/c24-recheck-assert.sh` (утверждения над сохранённым `C24/c24-config-input-control.sh`) | C24 | никуда | `bash C24/c24-recheck-assert.sh <gatekeeper-bin> <root> defect\|fixed` | `7e2f7b6` + `defect`: случай 1 `exit=1`; `f7c2cfe` + `fixed`: случай 1 `exit=0`; перекрёстные: код 1 |
| `RECHECK-1-mutations/K1..K9.patch` + `run-mutations.sh` | C23, C24 | патчи применяются к копии `f7c2cfe` | `bash RECHECK-1-mutations/run-mutations.sh <root-f7c2cfe> <trustcore-bin> [K1 ...]` | исходы по слоям GO/SH/C24/C23, таблица в отчёте |
| `run-recheck-1.sh` | C23, C24 | никуда | `bash run-recheck-1.sh <root-7e2f7b6> <root-f7c2cfe> <trustcore-bin>` | сверка `SHA256SUMS`, затем 8 прогонов; последняя строка `run-recheck-1: OK` |

Репродуктор C23 создан в сессии повторной приёмки (не восстановлен по памяти). Первая версия `$(newdir)` делила один каталог между случаями (счётчик в подоболочке) и краснела не из-за кода; это ошибка контроля, исправлена до записи результатов (см. отчёт, раздел 2).
