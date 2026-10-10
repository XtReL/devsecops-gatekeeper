# Акт приёмки ACT-0.1

| | |
|---|---|
| Репозиторий | `XtReL/devsecops-gatekeeper` |
| Коммит | `7e2f7b63fa71b4a9f3cb2a8c471a52119d7273f5` (`main`, 2026-09-28) |
| Дата | 2026-10-10 |
| Версия методики | 0.1 |
| Тип | самопроверка (автор проверяет свой репозиторий) |
| Ветка акта | `acceptance/act-v0` |

Код не исправлялся, файлы не удалялись. `.env` и файлы с секретами не
открывались; литералы, похожие на секреты, указаны только как «файл:строка»,
значения не выводились (проверялись лишь длина, энтропия и вид строки).
Положительные контроли выполнены во временных копиях (`git archive HEAD`)
и временных каталогах вне репозитория; все ключи в контролях созданы на
месте и удалены вместе с каталогами.

Отступления от «без сети», сделанные явно:
- первый же вызов `go version` сам скачал toolchain `go1.25.8`
  (`GOTOOLCHAIN=auto`, директива `go 1.25.8` в `go.mod`) — до того, как это
  стало видно;
- по решению владельца загружены модули Go по `go.sum`
  (`go mod download`, proxy.golang.org, только чтение публичных модулей) и
  `gosec v2.29.0` (через `scripts/check.sh`; `go run gosec@v2.29.0` при этом
  сам переключился на toolchain `go1.26.9` и скачал его). Ни к сервисам проекта, ни к
  GitHub API, ни к продакшену обращений не было; ветка журнала
  `gatekeeper-evidence` не скачивалась.

## Таблица заявлений

П — подтверждено, О — опровергнуто, Н — не определено.

| № | Заявление | Источник | Как проверено | Результат | Доказательство |
|---|---|---|---|---|---|
| C1 | Находки хранятся как SHA-256-отпечатки, без фрагментов секрета (режим Action: `result.json`, аттестация) | `README.md:3`, `README.md:44`; `internal/engine/engine.go:26-32` | Прогон: `go test ./...`; контроль — подложен маркер (`ghp_` + SHA-256 строки) во временную копию | П | Скан копии: код 1, `github-pat` в `marker.txt`; значение маркера в `result.json` — 0 вхождений; `TestScanResultNeverContainsTheSecretValue`, `TestRecordedEntryNeverContainsTestSecretValue` зелёные |
| C2 | «Ни одного символа секрета в логах и БД» (облачный режим) | `README.md:44` | Чтение `cmd/scanner/main.go:194-214` | П | В БД и лог пишется только `sha256:…` (в лог — первые 19 символов отпечатка); вывод `gitleaks` не захватывается. Прогона нет (нужны NATS/Postgres) |
| C3 | gitleaks закреплён по версии и контрольной сумме | `README.md:5` | Чтение `go.mod:16`, `go.sum`, `Dockerfile.scanner:11-14`; прогон проверки `gitleaksVersion` из `check.sh` | П | Action: `v8.30.1` по `go.sum`, `result.json` содержит `"gitleaksVersion": "v8.30.1"`; облако: `sha256sum -c` в Dockerfile. Само значение SHA-256 с релизом не сверялось (сеть) |
| C4 | «Сейчас работает облачный режим … для публичных репозиториев» | `README.md:9` | Не проверяется: нужны GitHub App, NATS, Postgres, SpiceDB | Н | Чтение показало: вебхук проверяет `repository:<числовой id>#reader` (`cmd/api/main.go:270`), а единственный код, выдающий права, пишет `repository:demo_repo` (`internal/billing/webhook.go:128`); `scripts/spicedb_init.go` пишет только схему. Пути, по которому настоящий вебхук проходит авторизацию, в коде нет |
| C5 | GitHub Action — «следующий основной режим» | `README.md:9` | Чтение | О | Тот же README в `README.md:22` называет Action основным способом; `action.yml` и dogfooding (`.github/workflows/gatekeeper.yml`) уже есть |
| C6 | `docker compose config -q` без `.env` завершится ошибкой | `README.md:36` | Прогон во временной копии (без запуска контейнеров) | П | Без `.env`: код 1 (`required variable SPICEDB_TOKEN is missing`). Но с `.env`, где задан только `SPICEDB_TOKEN`, — код 0, `POSTGRES_PASSWORD` подставлен пустым в 2 строки подключения (см. находки) |
| C7 | В репозитории нет секретов, ключей и паролей по умолчанию | `README.md:42` | Прогон самоскана; поиск литералов (`grep`, вывод только путь:строка, длина, энтропия) | О | Самоскан: 0 находок. Но есть литералы-секреты dev/test: `scripts/stripe_sim.go:20` (len 19, H≈3.15), `scripts/github_sim.py:8` (len 27, H≈3.57), `internal/billing/webhook_test.go.bak:201` (len 23, H≈3.24, префикс `whsec_`), `.github/workflows/ci.yml:80`, пароль по умолчанию в `.github/workflows/ci.yml:82`. Встроенные правила gitleaks их не видят. Реальных секретов не выявлено |
| C8 | «Никаких обходов авторизации: идентификаторы берутся только из подписанного вебхука» | `README.md:43`; `cmd/api/main.go:252-253` | Чтение `cmd/api/main.go` | О | `/api/v1/findings` и `/api/v1/findings/status` (`cmd/api/main.go:104-105`) без аутентификации берут субъект из заголовка `X-User-Login` (`:132`, `:332`) и передают его в SpiceDB. Прогон невозможен без SpiceDB/Postgres |
| C9 | GitHub Actions закреплены на полных SHA | `README.md:45`, `CLAUDE.md:7` | `grep uses:` по `.github/workflows/*.yml`, `examples/*.yml`, `action.yml` | П | Все сторонние `uses:` — 40-символьные SHA с тегом; остальные — `./` и шаблонный `<FULL_SHA>` в примере |
| C10 | Токены доступа не передаются через очередь | `README.md:46` | Чтение `internal/broker/nats.go:18-26`, `cmd/api/main.go:293-298` | П | В `TaskPayload` нет полей токена, публикуется только он |
| C11 | API проверяет HMAC вебхука GitHub | `README.md:15` | Чтение `cmd/api/main.go:199-212` | П | `github.ValidatePayload` до разбора JSON; пустой `WEBHOOK_SECRET` → 500, и `config.Validate` его требует |
| C12 | Ресурс SpiceDB — числовой ID репозитория | `README.md:17`, `cmd/api/main.go:265-267` | Чтение | О | Вебхук — числовой ID; `/api/v1/findings*` — имя репозитория из запроса или БД (`cmd/api/main.go:148`, `:356`); биллинг — `demo_repo` (`internal/billing/webhook.go:128`). Три разные модели идентификатора |
| C13 | Оптимистичная запись: до 5 попыток с нарастающей паузой, после 5 неудач — явный отказ | `docs/adr/0001-action-evidence.md:16-17` | Прогон `evidence-push_test.sh`; контроль — `pre-receive`-хук в bare-репозитории отклоняет push | П | Отказ 1 раз: попытка 2 успешна, пауза 6 с, `trustcore verify` → OK. Отказ всегда: 5 попыток, паузы 5/8/22/34 с, `giving up after 5 attempts`, код 1, 69 с |
| C14 | Идемпотентность по `run_id` + `run_attempt` | `docs/adr/0001-action-evidence.md:18` | Прогон: `TestRecordIsIdempotentByRunIDAndAttempt`, `TestRunRecordExitCodes`, `evidence-push_test.sh` | П | Повтор → код 3, новая запись и коммит не появляются |
| C15 | Ключ только из переменной окружения, на диск не пишется, не выводится | `docs/adr/0001-action-evidence.md:42`; `action.yml:11-15`; `internal/evidence/evidence.go:154-156` | Прогон тестов; контроль — `record` с тремя неверными ключами-маркерами | П | Без ключа — код 2, чтения файла нет; мусор, PEM неверного типа и RSA-ключ → код 2, материал ключа в выводе — 0 вхождений (детектор проверен на строке с маркером — срабатывает) |
| C16 | Ключ «never passed to another step» | `action.yml:15` | Чтение `action.yml`, `docs/adr/0003-distribution.md:31` | О | `env` шага `uses:` видят все внутренние шаги composite-вызова (`Validate mode`, `chmod`, `Record`) — это и записано в ADR 0003. Все три шага свои, вреда нет; формулировка шире реальности |
| C17 | В репозитории нет `workflow_run`/`pull_request_target`, это проверяется в CI | `docs/adr/0001-action-evidence.md:43` | Прогон `scripts/lint-workflows.sh`; контроль — подложен workflow с запрещённым триггером | П | Чисто: код 0; подложенный (блочный и flow-стиль) — код 1. Не ловится файл с расширением `.YML` (см. слепые зоны) |
| C18 | Сканер детерминирован, повтор даёт побайтно тот же `result.json` | `docs/adr/0001-action-evidence.md:47`, `:56` | Прогон: самоскан дважды + `cmp`; контроль — одно содержимое по двум разным путям | П | `cmp`: идентичны в обоих случаях; тесты детерминизма зелёные |
| C19 | `.git` не сканируется, находки отсортированы и схлопнуты, пустой массив, без строк и путей | `docs/tasks/stage3.md:154-158`; `internal/engine/engine.go:42-45` | Прогон тестов; контроль — один токен дважды + второй токен в одном файле | П | 2 находки (дубль схлопнут), сортировка по отпечатку соблюдена; `.git` игнорируется (тест + контроль `.git/hooks`) |
| C20 | Коды выхода `scan`: 0/1/2, `record`: 0/2/3 | `cmd/gatekeeper/main.go:21-22` | Прогон `cmd/gatekeeper` тестов и контролей | П | Все четыре кода наблюдались |
| C21 | Без версии gitleaks результат не выпускается (fail secure) | `internal/engine/engine.go:46-47` | Прогон: тест со стабом + проверка настоящего бинарника в `check.sh` | П | `TestScanFailsWhenGitleaksVersionIsUnavailable` зелёный; `check: verify gitleaks version …` пройден |
| C22 | SARIF редактирует секрет | `internal/engine/engine.go:88-91` | Прогон теста; контроль `--sarif` с маркерами | П | Маркеры в SARIF — 0, `REDACTED` — 3 |
| C23 | Конфиг эпохи — строгий JSON | `internal/evidence/evidence.go:58-61`; `docs/tasks/rotation.md:17` | Прогон `evidence-target` на неверных конфигах | О | `{"epoch":0}`, пустой файл, `2.0` → код 2. Но `{"epoch":2}{"epoch":5}` → код 0, эпоха 2 (хвост молча игнорируется); опечатка в пути `--config` → код 0, эпоха 1 |
| C24 | Вход `config` действует в режимах `target` и `record` | `action.yml:40` | Чтение `scripts/evidence-push.sh:54-61`; контроль — запуск тела шага `record` из `action.yml` с журналом эпохи 2 и конфигом по нестандартному пути | О | `evidence-push.sh` не передаёт `--config`, `record` читает `.gatekeeper/evidence.json` из cwd: ветка из `config` (e2), origin — по умолчанию (e1) → код 1; с копией конфига по пути по умолчанию → код 0 |
| C25 | Входы и контекст GitHub не подставляются в `run:` через `${{ }}` | `action.yml:8-10`; `CLAUDE.md:8` | Разбор YAML всех `run:` (`.github/workflows`, `examples`, `action.yml`); контроль — подложена подстановка | П | 28 блоков `run:`, подстановок 0; подложенная находится. Автоматической проверки в CI нет — правило держится на ревью |
| C26 | Неизвестный `mode` — ошибка | `docs/tasks/distribution.md:13`; `action.yml:64-75` | Прогон тела шага `Validate mode` из `action.yml` | П | `build/scan/target/record` → 0; `bogus` и пустой → 1 |
| C27 | `description` action ≤ 125 символов | `docs/tasks/distribution.md:12` | Подсчёт | П | 105 символов |
| C28 | В задании `record` нет Go и сборки; ключ только в `env` последнего шага | `docs/adr/0003-distribution.md:34-36`, `:60` | Чтение `.github/workflows/gatekeeper.yml:69-120`, `examples/client-workflow.yml:75-130` | П | Шаги: checkout, download-artifact, `./` target, checkout журнала, `./` record с ключом в `env` только этого шага |
| C29 | `record` — только push в ветку по умолчанию, права `contents: write` и больше ничего | `docs/adr/0001-action-evidence.md:37-38` | Чтение `.github/workflows/gatekeeper.yml:75-80` | П | Условие `if:` и `permissions` совпадают с ADR. Запустить Actions локально нельзя |
| C30 | Секрет environment недоступен PR и другим веткам | `docs/onboarding.md:41-45`; `docs/tasks/stage3.md:151` | Не проверяется: настройки GitHub, нужен доступ к репозиторию | Н | Эмпирический тест в `docs/tasks/stage3.md:151` отмечен ⬜ (не выполнен) |
| C31 | `check.sh` запускает то же, что CI | `scripts/check.sh:2-3`; `CLAUDE.md:4` | Сравнение `check.sh` с `ci.yml` и `gatekeeper.yml` | О | Не воспроизведено: задание `action self-test` (`.github/workflows/gatekeeper.yml:123-…`: режимы action, mode-валидация, `record` через action), GitGuardian (оговорено в `check.sh:6-8`). Самоскан строже CI (код 1 валит `check.sh`, `ci.yml` его допускает) |
| C32 | Тест покрывает гонку, когда конкурент пишет «между нашим fetch и push» | `scripts/evidence-push_test.sh:9-11` | Чтение `scripts/evidence-push_test.sh:100-115`; контроль C13 | О | Конкурент пишет до первого fetch устаревшей копии (`:111`), push не отклоняется, ветка повтора с паузой тестом не исполняется. Что ветка работает, показал только контроль C13 |
| C33 | Тест проверяет, что запись журнала не содержит материала ключа | `internal/evidence/evidence_test.go:274-275`, `:307` | Чтение | О | Сравнение с PEM-текстом целиком (`bytes.Contains(entry, pemBytes)`): утечка сырых байт, DER или части base64 этот тест не провалит |
| C34 | «Запуск тестов на моковых переменных» (Stripe и др.) | `.github/workflows/ci.yml:78-84` | Прогон `go test ./...`; чтение | О | В `internal/billing` нет тестов (`[no test files]`): единственный тест переименован в `webhook_test.go.bak` и не компилируется. Моковые переменные никто не читает |
| C35 | Биллинг обрабатывает `invoice.paid` и защищён от повторной обработки (`stripe_processed_events`) | `internal/billing/README.md:14-15`, `:25`, `:37-41` | `grep` по коду | О | `invoice.paid` в коде — 0; `stripe_processed_events` есть только в DDL (`internal/db/database.go:73-80`), обращений 0 |
| C36 | «Все входящие вебхуки от Stripe проходят криптографическую верификацию» | `internal/billing/README.md:30` | Контроль во временной копии: тест вызывает `HandleStripeWebhook` с событием, подписанным пустым ключом | О | `STRIPE_WEBHOOK_SECRET` пуст → HTTP 200 (подделка принята); секрет задан → HTTP 400. `config.Validate` (`internal/config/config.go:34-57`) секрет Stripe не требует |
| C37 | `m.Ack()` — «успешное завершение всего цикла» сканирования | `cmd/scanner/main.go:159` | Чтение; контроль — `parseReport` на отчёте без поля `Secret` (временная копия) | О | Ошибка gitleaks (код ≠ 0, 1) только логируется (`:150`), задача подтверждается и пропадает; непроверенное приведение типа (`:195`) → panic `interface conversion` в обработчике NATS |
| C38 | `gatekeeper evidence-init` «используется для эпох ≥ 2» | `docs/onboarding.md:118-121` | Чтение `cmd/gatekeeper/main.go:112-116` | О | Код и ADR 0002: журнал эпохи ≥ 2 создаёт `trustcore rotate`, а не `evidence-init` |
| C39 | `go install …/cmd/gatekeeper@…` не резолвится: модуль назван `devsecops-gatekeeper` | `docs/onboarding.md:78-81` | Чтение `go.mod:1` | П | `module devsecops-gatekeeper`. `go install` не запускался (сеть) |
| C40 | `.gitignore`: «абсолютный запрет на коммит» секретов и ключей | `.gitignore:1` | Прогон `git check-ignore` | О | Игнорируются `.env*`, `*.pem`, `*.key`; не игнорируются `credentials.json`, `secrets/`, `id_ed25519`, `*.p12` (часть есть только в `.cursorignore`) |
| C41 | Публичный ключ журнала — `.gatekeeper/evidence.pub` | `docs/adr/0001-action-evidence.md:26` | `openssl pkey -pubin` | П | `ED25519 Public-Key`. Соответствие приватному ключу в секрете не проверяется (нет доступа и не нужно) |
| C42 | Посторонний может независимо проверить журнал | `README.md:28-30`; `docs/VERIFY.md` | Не проверяется: нужен clone публичной ветки с GitHub (сеть) | Н | Локально сам механизм проверен (`trustcore verify` в C13 и в `check.sh`), опубликованный журнал — нет |
| C43 | В аттестации закреплено всё, что нужно для повтора | `docs/adr/0001-action-evidence.md:47-54` | Чтение `internal/engine/engine.go:22`, `internal/evidence/evidence.go:283`; `git log` | О | `gatekeeperVersion` — константа `0.1.0` с фазы 2 (`8ae74c8`), хотя код `internal/`/`cmd/gatekeeper` менялся (17 коммитов). Ревизия action в аттестации не записана; для клиента она восстановима только из его workflow-файла в том же коммите |

## Итог

**Подтверждено 23 из 43** (опровергнуто 17, не определено 3).

| Результат | Заявления |
|---|---|
| Подтверждено (23) | C1, C2, C3, C6, C9, C10, C11, C13, C14, C15, C17, C18, C19, C20, C21, C22, C25, C26, C27, C28, C29, C39, C41 |
| Опровергнуто (17) | C5, C7, C8, C12, C16, C23, C24, C31, C32, C33, C34, C35, C36, C37, C38, C40, C43 |
| Не определено (3) | C4, C30, C42 |

`scripts/check.sh` перед push коммита акта: `check: OK` (полный вывод
приложен к отчёту автору; команды — в разделе «Команды для повторения»).

## Риски по цене пропуска

**Высокая цена (облачный режим):**
1. C8 — субъект авторизации из неподписанного заголовка `X-User-Login`.
   Кто знает логин участника с правами `writer`, читает отчёты о находках
   любого его репозитория и меняет их статус (`status` не валидируется,
   `cmd/api/main.go:366`). Утечка сведений о секретах клиента и подавление
   алертов.
2. C36 — при пустом `STRIPE_WEBHOOK_SECRET` подделанный
   `checkout.session.completed` активирует подписку любому tenant.
   Конфигурация, при которой это происходит, проходит `config.Validate` и
   `docker compose config` без ошибок.
3. Отпечатки без соли (новый класс Н1). В режиме Action отпечатки
   находок попадают в подписанную аттестацию (`findings` в аннотациях) и
   в ветку журнала. Для слабого секрета (пароль, короткий ключ) догадку
   можно подтвердить офлайн: контроль сверил кандидата с отпечатком из
   `result.json` (совпадение найдено).

**Средняя цена:**
4. C37 — сбой сканера (ошибка gitleaks, panic на отчёте, сбой клона)
   подтверждает задачу и не оставляет следа; `/api/v1/findings` для
   репозитория без строк отдаёт `null` — для потребителя это «чисто».
5. Слепые зоны движка: история git не сканируется (секрет, удалённый
   следующим коммитом, не находится — контроль: код 0); пути из allowlist
   gitleaks (`node_modules/`, `go.sum`, `package-lock.json`, `*.png`)
   пропускаются — контроль: код 0.
6. C24/C23 — нестандартный путь `config` и опечатка в пути. Первый случай
   падает громко, но с сообщением про ключ (Н2); опечатка молча даёт эпоху 1.
7. Тайм-аут CI: `go test -race -timeout 30s`, а `cmd/gatekeeper` на
   холодном кэше шёл 29,0 с (TestMain собирает бинарник). На тёплом — 2,3 с.
   Запас 1 с: риск нестабильного красного CI.
8. Плавающие образы вне CI: `golang:alpine`, `alpine:latest`
   (`Dockerfile*`), `authzed/spicedb:latest` (`docker-compose.yml:21`,
   `:29`), `:latest` в `k8s/*.yaml`. Утверждение C9 касается только CI.

**Низкая цена:** документация отстала (C5, C35, C38), формулировки шире
поведения (C16, C40), мёртвый код безопасности (Н3), dev-литералы (C7).

## Решение

**Режим GitHub Action (`action.yml`, `cmd/gatekeeper`, `internal/engine`,
`internal/evidence`, `scripts/evidence-push.sh`): принять с условиями.**
Ядро заявлений о журнале доказательств подтвердилось прогонами и
положительными контролями (C1, C13–C15, C17–C22, C25–C29).

Условия:
1. Вход `config` либо передаётся в `gatekeeper record` (`--config`), либо
   убирается из `record` в описании входа (C24).
2. Явно задокументировать или устранить: хвост JSON в конфиге и молчаливую
   эпоху 1 при опечатке в явно указанном `--config` (C23).
3. Решение по отпечаткам без соли в публичном журнале (Н1): принять риск
   письменно в ADR или сменить схему (HMAC с ключом клиента или отказ
   публиковать отпечатки).
4. Довести тест гонки до отклонённого push (C32) и заменить проверку утечки
   ключа на проверку сырых байт ключа (C33).
5. Поднять запас тайм-аута тестов или вынести сборку из TestMain (риск 7).
6. Привести в соответствие заявления C31 (`check.sh` ≠ CI), C43
   (`gatekeeperVersion`), C16.

**Облачный режим (`cmd/api`, `cmd/scanner`, `internal/billing` и связанные):
не принимать.** До исправления C8, C36, C37 и согласования модели
идентификатора (C12, C4) не разворачивать. В README убрать «сейчас
работает облачный режим» или пометить его как непроверенный (C4, C5).

## Слепые зоны акта

- Ничего не запускалось в GitHub Actions: условия `if:`, environment,
  ruleset, кэш `setup-go` внутри composite action, наследование `env` —
  только чтением (C28–C30).
- Облачный режим не запускался: нет NATS, Postgres, SpiceDB, GitHub App.
  Выводы C2, C4, C8, C10–C12 — по чтению кода.
- Опубликованный журнал `gatekeeper-evidence` и VERIFY.md не проверены
  (C42); SHA-256 архива gitleaks в `Dockerfile.scanner` с релизом не сверен.
- GitGuardian не запускался (нужен ключ API).
- gosec: 0 проблем при 14 подавлениях `#nosec` и исключённых G104/G108;
  подавления по существу не пересматривались.
- `lint-workflows.sh` смотрит только `*.yml`/`*.yaml` в нижнем регистре;
  распознаёт ли GitHub `.YML`, не проверялось.
- Воспроизведение по аннотации `reproduce` (`gatekeeper scan --source .`)
  в рабочей копии разработчика захватит неотслеживаемые файлы; нужен чистый
  clone. Не проверялось, оговорено ли это в VERIFY.md.
- Сторонние модули (trust-core, gitleaks) не аудировались — им доверяли
  как зависимостям, закреплённым через `go.sum`.

## Команды для повторения

```bash
# окружение: без глобальной конфигурации git, рабочий каталог вне репозитория
S=$(mktemp -d); R=$(pwd)
GOFLAGS=-mod=readonly go mod download
scripts/check.sh                                   # C9, C14, C17, C19-C22, C31
go test -race -count=1 -v ./...                    # тесты, тайм-ауты холодного кэша
GOFLAGS=-mod=readonly go build -o $S/gatekeeper ./cmd/gatekeeper
GOFLAGS=-mod=readonly go build -o $S/trustcore github.com/XtReL/trust-core/cmd/trustcore

# C1, C18, C22: маркер в копии, детерминизм, SARIF
mkdir $S/pc && git archive HEAD | tar -x -C $S/pc
b=$(printf 'acceptance-marker' | sha256sum | cut -c1-36); t=gh; printf 'token = "%s"\n' "${t}p_$b" > $S/pc/marker.txt
$S/gatekeeper scan --source $S/pc --out $S/pc.json --sarif $S/pc.sarif; echo $?   # ожидается 1
grep -c "${t}p_$b" $S/pc.json $S/pc.sarif                                       # ожидается 0 и 0
$S/gatekeeper scan --source . --out $S/r1.json; $S/gatekeeper scan --source . --out $S/r2.json; cmp $S/r1.json $S/r2.json

# C23: конфиг
$S/gatekeeper evidence-target --repo o/r --config /nonexistent.json                 # код 0, эпоха 1
printf '{"epoch":2}{"epoch":5}' > $S/t.json; $S/gatekeeper evidence-target --repo o/r --config $S/t.json  # код 0

# C17, C25, C26: lint и action.yml
cp -r $S/pc $S/pc2; w=pull_request; printf 'on:\n  %s:\n' "${w}_target" > $S/pc2/.github/workflows/p.yml
(cd $S/pc2 && scripts/lint-workflows.sh); echo $?                                   # ожидается 1
python3 -I -c 'import yaml;print(yaml.safe_load(open("action.yml"))["runs"]["steps"][0]["run"])' > $S/v.sh
MODE=bogus bash -eo pipefail $S/v.sh; echo $?                                       # ожидается 1

# C13: повтор push — в bare-репозиторий журнала положить hooks/pre-receive,
#      отклоняющий первые N push, и запустить scripts/evidence-push.sh
#      (шаги инициализации — как в scripts/evidence-push_test.sh:129-148)
# C24: тело шага id=record из action.yml, CONFIG=cfg/custom.json с {"epoch": 2},
#      журнал эпохи 2 (evidence-init --epoch 2), cwd без .gatekeeper/evidence.json
# C36: во временной копии internal/billing/*_test.go с
#      webhook.GenerateTestSignedPayload(Secret: "") и пустым STRIPE_WEBHOOK_SECRET
# C37: во временной копии cmd/scanner/*_test.go: parseReport на [{"Description":"x","File":"f"}]
# C6:  во временной копии: docker compose config -q (без .env; затем .env только с SPICEDB_TOKEN)
# C40: git check-ignore -v credentials.json secrets/a id_ed25519 x.p12
```

## Находки по классам

**Утверждение шире проверки**
- C7: «нет секретов» проверяется только встроенными правилами gitleaks,
  которые dev-литералы не видят.
- C16: «never passed to another step» — `env` видят все шаги composite.
- C25: правило «никаких `${{ }}` в `run:`» верно сейчас, но в CI не
  проверяется.
- C31: `check.sh` «exactly what CI runs» — без `action self-test`.
- C40: «абсолютный запрет» в `.gitignore` покрывает не все типичные файлы с
  секретами.
- C43: «закреплено всё для повтора» при неизменной `gatekeeperVersion`.
- Тесты движка (`internal/engine/engine_test.go:45-46`, `:70-71`) кладут
  в оба файла один и тот же токен (один seed PRNG): сортировка по
  `RuleID`/`Fingerprint` и схлопывание дублей тестами не покрыты.
  Поведение подтверждено только контролем C19.

**Тест проходит вхолостую**
- C32: ветка «push отклонён → пауза → повтор» в `evidence-push_test.sh`
  не исполняется.
- C33: проверка утечки ключа сравнивает с PEM-текстом целиком.
- C34: моковые переменные Stripe в CI при отсутствии тестов биллинга
  (`webhook_test.go.bak`).

**Ошибка в тесте похожа на ошибку кода** — не выявлено.

**Противоречивые требования**
- C12: три модели идентификатора репозитория в SpiceDB (числовой ID, имя,
  `demo_repo`). Отсюда же C4: оплата выдаёт права не на тот ресурс, который
  проверяет вебхук.
- ADR 0001/`docs/tasks/stage3.md:90` («`evidence-init` нужна клиентам»)
  против `docs/onboarding.md:76-84` («клиенту бинарник взять негде»).

**Документация отстала от кода**
- C5 (README: Action — «следующий» режим), C35 (`invoice.paid`,
  идемпотентность Stripe), C38 (`evidence-init` для эпох ≥ 2).

**Неверная конфигурация принимается молча**
- C36: пустой `STRIPE_WEBHOOK_SECRET` → подпись Stripe не защищает.
- C6: `.env` без `POSTGRES_PASSWORD` → пустой пароль в строках
  подключения, `docker compose config` — код 0 (только предупреждение).
- C23: хвостовые JSON-объекты и опечатка в явном `--config` → эпоха 1.
- `evidence-target --repo` не валидирует `OWNER/REPO`
  (`'evil repo/../x'` → код 0, origin с пробелом и `..`);
  `ValidateRepoFullName` пропускает `owner/..`, `owner/.git`, `-owner/repo`
  (контроль во временной копии).

**Скрытый сбой**
- C37: ошибка gitleaks или сбой клона → `Ack`, задача исчезает; panic в
  `parseReport` роняет обработчик.
- `internal/billing/webhook.go:128-133`: сбой записи прав в SpiceDB только
  логируется, Stripe получает 200 — подписка оплачена, доступа нет.

**Слепое доверие заголовкам**
- C8: `X-User-Login` как субъект авторизации в `/api/v1/findings*`.

**Отсутствие строки читается как ноль**
- `/api/v1/findings`: нет строк (в том числе после скрытого сбоя
  сканирования) → `null`, то есть «находок нет».
- `LoadConfig`: отсутствующий файл (в том числе опечатка в пути) →
  эпоха 1 (C23). Для пути по умолчанию это задокументированное требование,
  для явно переданного `--config` — нет.

### Новые классы

- **Н1. Хэш без соли выдаётся за маскировку.** `sha256(secret)` не
  раскрывает символов секрета (C1 верно), но для секретов с малой
  энтропией служит оракулом подтверждения догадки. Опасно там, где
  отпечатки публикуются: подписанная аттестация и ветка журнала в
  публичном репозитории.
- **Н2. Диагностика указывает не на ту причину.** Несовпадение origin
  (C24) сообщается как `checkpoint does not verify under this log key`;
  любой отказ push (хук, права, ruleset) в `evidence-push.sh:80` назван
  `concurrent writer`. Оператор начнёт искать проблему не там: в ключе или
  в гонке.
- **Н3. Мёртвый код безопасности.** Три неиспользуемые реализации
  проверки HMAC (`internal/middleware/hmac.go`, `signature.go`,
  `webhook.go`), неиспользуемые `internal/handler`, `internal/authz`,
  `internal/cache`, `internal/scanner`, тест `webhook_test.go.bak`,
  закомментированный блок «ЗАКОММЕНТИРОВАН ДЛЯ БАЙПАССА»
  (`internal/iam/spicedb.go:108`). Создают видимость защит, которых на
  пути запроса нет, и сбивают ревью.
- **Н4. Запас тайм-аута меньше разброса прогона.** Лимит 30 с при
  холодном прогоне 29,0 с: зелёный CI держится на тёплом кэше.
