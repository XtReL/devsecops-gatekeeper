# Подключение клиента к Gatekeeper Action

Разовая настройка репозитория клиента перед первым запуском шаблона
[`examples/client-workflow.yml`](../examples/client-workflow.yml)
(`docs/adr/0003-distribution.md`). Решения ADR 0001 и ADR 0003 эта
инструкция не меняет, только описывает шаги.

Всё ниже выполняется **на устройстве владельца** (не в CI): CI никогда не
видит закрытую часть ключа до момента, когда секрет уже сохранён в GitHub.

`OWNER/REPO` — репозиторий клиента, к которому подключается Gatekeeper.

## 1. Ключ Ed25519 на устройстве владельца

```bash
trustcore keygen -out gatekeeper-evidence -name "github.com/OWNER/REPO/gatekeeper-evidence/v1"
```

Выводит `gatekeeper-evidence.key` (закрытый ключ, PKCS#8 PEM),
`gatekeeper-evidence.pub` (публичный ключ), `key id` и `vkey`
(note-verifier key для свидетелей).

- `gatekeeper-evidence.key` не коммитится, не публикуется и после шага 4
  остаётся только на устройстве владельца (резервная копия — по вашей
  собственной практике хранения секретов, вне этого репозитория).
- `key id` и `vkey` сохраните отдельно: они понадобятся аудитору и
  свидетелю (этап 6) для проверки журнала независимо от копии в
  репозитории.
- Один и тот же ключ подписывает и записи журнала, и чекпоинты (ADR 0001,
  решение B: в режиме Action оператор журнала и аттестатор — одна
  сторона, клиент).

## 2. Environment `gatekeeper-evidence` и секрет

В настройках репозитория (Settings → Environments) создайте environment
`gatekeeper-evidence` и ограничьте деплой только веткой по умолчанию
(Deployment branches and tags → Selected branches → добавить только её,
без wildcard). Задание `record` объявляет `environment: gatekeeper-evidence`
именно поэтому: секрет ниже недоступен ни PR, ни любой другой ветке.

Секрет кладите из stdin, а не аргументом командной строки (аргументы
попадают в историю шелла и список процессов):

```bash
gh secret set GATEKEEPER_SIGNING_KEY \
  --env gatekeeper-evidence \
  --repo OWNER/REPO \
  < gatekeeper-evidence.key
```

## 3. Журнал: `gatekeeper evidence-init` и orphan-ветка

Журнал живёт в отдельной ветке `gatekeeper-evidence` без общей истории с
кодом (ADR 0001, решение A). Инициализация — тоже на устройстве владельца,
один раз, с тем же ключом:

```bash
git clone https://github.com/OWNER/REPO.git evidence-init
cd evidence-init
git checkout --orphan gatekeeper-evidence
git rm -rf .

gatekeeper evidence-init \
  --evidence . \
  --repo OWNER/REPO \
  --key ../gatekeeper-evidence.key

git add -A
git commit -m "gatekeeper: initialise evidence log (epoch 1)"
git push origin gatekeeper-evidence
```

`evidence-init` создаёт `checkpoint`, каталог `entries/` (с `.gitkeep`,
чтобы git не терял пустой каталог) и не читает `GATEKEEPER_SIGNING_KEY` —
эта команда никогда не запускается в CI (`docs/adr/0001-action-evidence.md`).

## 4. Ruleset для ветки журнала

Ветка `gatekeeper-evidence` (и любая `gatekeeper-evidence-e<n>` после
ротации, `docs/tasks/rotation.md`) не должна допускать удаление и force
push. В настройках репозитория (Settings → Rules → Rulesets) создайте
ruleset с целевой веткой `gatekeeper-evidence*` и правилами «Restrict
deletions» и «Block force pushes».

**PR для этой ветки не требуется** — если включить обязательный review
для неё, задание `record` не сможет запушить запись (ADR 0001, решение A).
Гарантию неизменности журнала даёт не ruleset, а независимые копии
чекпоинтов у других сторон (аудитор, на этапе 6 — свидетель): администратор
репозитория технически может обойти ruleset или удалить запуски CI.

## 5. `.gatekeeper/evidence.json`

Закоммитьте в ветку по умолчанию:

```json
{"epoch": 1}
```

Это единственный источник истины об эпохе в репозитории клиента; ветка и
origin журнала всегда выводятся из номера эпохи (`gatekeeper
evidence-target`), а не хранятся отдельно. Отсутствие файла тоже означает
эпоху 1 (обратная совместимость), но лучше закоммитить его явно.

## 6. Шаблон workflow

Скопируйте [`examples/client-workflow.yml`](../examples/client-workflow.yml)
в `.github/workflows/gatekeeper.yml` и замените `<FULL_SHA>` на полный SHA
нужного релиза (тег — в комментарии рядом, как и во всех остальных actions
в шаблоне). Два задания:

- `scan` — на `pull_request` и `push`, без секретов: собирает `gatekeeper`
  из исходников action по закреплённому SHA, сканирует, выгружает
  `result.json` и бинарник артефактом. Ничего не падает на находках —
  решение принимает следующий шаг того же задания.
- `record` — только на `push` в ветку по умолчанию, `environment:
  gatekeeper-evidence`: скачивает артефакт, подписывает результат и
  добавляет запись в журнал. Ключ — только в `env` последнего шага.

## 7. Публичный ключ в репозитории и первая проверка

Закоммитьте `gatekeeper-evidence.pub` в ветку по умолчанию как
`.gatekeeper/evidence.pub`:

```bash
cp gatekeeper-evidence.pub OWNER-REPO-checkout/.gatekeeper/evidence.pub
```

Этот файл — только для сверки; **аудитор получает ключ от вас напрямую**,
а не через репозиторий (ADR 0001, решение B) — иначе тот, кто может писать
в ветку по умолчанию, мог бы подменить и запись, и ключ для её проверки.

После первого запуска `record` на push в ветку по умолчанию проверьте
журнал:

```bash
git clone --branch gatekeeper-evidence --single-branch \
  https://github.com/OWNER/REPO.git evidence-check

trustcore verify \
  -log evidence-check \
  -origin "github.com/OWNER/REPO/gatekeeper-evidence/v1" \
  -log-pub .gatekeeper/evidence.pub \
  -attester-pub .gatekeeper/evidence.pub
```

Если проверка прошла — журнал подключён. Дальнейшая ротация ключа
описана в `docs/tasks/rotation.md` и `docs/runbooks/key-rotation.md`.
