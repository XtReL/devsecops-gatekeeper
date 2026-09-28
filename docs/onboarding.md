# Подключение клиента к Gatekeeper Action

Разовая настройка репозитория клиента перед первым запуском шаблона
[`examples/client-workflow.yml`](../examples/client-workflow.yml)
(`docs/adr/0003-distribution.md`). Решения ADR 0001 и ADR 0003 эта
инструкция не меняет, только описывает шаги.

Всё ниже выполняется **на устройстве владельца** (не в CI): CI никогда не
видит закрытую часть ключа до момента, когда секрет уже сохранён в GitHub.

`OWNER/REPO` — репозиторий клиента, к которому подключается Gatekeeper.

## 1. Ключ Ed25519 на устройстве владельца

`trustcore` ставится одной командой (нужен установленный Go):

```bash
go install github.com/XtReL/trust-core/cmd/trustcore@v0.2.0
```

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

Если `gh secret set` отвечает `HTTP 404`, значит команда выполнена раньше
создания environment: сначала завершите первую половину этого шага
(Settings → Environments → создать `gatekeeper-evidence`), затем повторите
команду.

На Windows `gh` ставится одной командой (winget идёт с Windows по
умолчанию, отдельно ставить не нужно):

```powershell
winget install --id GitHub.cli
```

После установки `gh` не появляется в текущем сеансе PATH — перезапустите
терминал целиком (в VS Code — весь редактор, не только вкладку терминала),
прежде чем выполнять команду выше.

## 3. Журнал: `trustcore init` и orphan-ветка

Журнал живёт в отдельной ветке `gatekeeper-evidence` без общей истории с
кодом (ADR 0001, решение A). Инициализация — тоже на устройстве владельца,
один раз, тем же `trustcore` (шаг 1) и тем же ключом — **не** бинарником
`gatekeeper`: его клиенту взять негде, `go.mod` этого репозитория объявляет
модуль как `devsecops-gatekeeper`, а не как полный путь
`github.com/XtReL/devsecops-gatekeeper`, поэтому `go install
github.com/XtReL/devsecops-gatekeeper/cmd/gatekeeper@...` не резолвится.
`gatekeeper` собирается только внутри action из исходников по закреплённому
SHA (`mode: build`, ADR 0003, шаг 6 ниже) — устанавливать его отдельно не
нужно.

```bash
git clone https://github.com/OWNER/REPO.git evidence-init
cd evidence-init
git checkout --orphan gatekeeper-evidence
git rm -rf .

trustcore init \
  -log . \
  -origin "github.com/OWNER/REPO/gatekeeper-evidence/v1" \
  -log-key ../gatekeeper-evidence.key
touch entries/.gitkeep
printf '* -text\n' > .gitattributes

git add -A
git commit -m "gatekeeper: initialise evidence log (epoch 1)"
git push origin gatekeeper-evidence
```

`trustcore init` создаёт `checkpoint` и каталог `entries/`; `entries/.gitkeep`
нужен отдельной командой, чтобы git не терял пустой каталог. `trustcore` не
читает `GATEKEEPER_SIGNING_KEY` — эта инициализация выполняется на устройстве
владельца и никогда в CI (`docs/adr/0001-action-evidence.md`).

`.gitattributes` со строкой `* -text` коммитится рядом с `checkpoint` и
`entries/.gitkeep` **обязательно**: `checkpoint` — подписанная нота, а
каждый файл в `entries/` — хэшируемый лист Меркла, оба должны дойти до
клона побайтно теми же, что были подписаны. Без `.gitattributes`
дефолтная настройка Windows (`core.autocrlf=true`) при клонировании
превращает `LF` в `CRLF` в обоих, и `trustcore verify` падает с
«malformed note» — подпись перестаёт сходиться с изменившимися байтами.
`* -text` отключает атрибут `text` для всех файлов ветки журнала, поэтому
git считает их бинарными и не трогает переводы строк независимо от
`core.autocrlf` клона. (Команда `gatekeeper evidence-init`, используемая
для эпох ≥ 2 или для повторной инициализации этим бинарником, создаёт
`.gitattributes` автоматически — здесь она недоступна клиенту, поэтому
файл создаётся вручную, как показано выше.)

## 4. Ruleset для ветки журнала

Ветка `gatekeeper-evidence` (и любая `gatekeeper-evidence-e<n>` после
ротации, `docs/tasks/rotation.md`) не должна допускать удаление и force
push. В настройках репозитория (Settings → Rules → Rulesets) создайте
ruleset с двумя явными целями — веткой `gatekeeper-evidence` и шаблоном
`gatekeeper-evidence-e*` (ADR 0002 в trust-core; тот же список целей, что
`docs/runbooks/key-rotation.md` использует при ротации) — и правилами
«Restrict deletions» и «Block force pushes». Не задавайте один широкий
шаблон `gatekeeper-evidence*`: вторую цель нужно вводить так же, как её
позже добавляет runbook ротации, а не отдельным шаблоном, не описанным
больше нигде.

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
в `.github/workflows/gatekeeper.yml` и замените каждый `<FULL_SHA>` на
полный SHA коммита нужного релизного тега этого репозитория (например,
`v0.1.0`); сам тег впишите в комментарий `<TAG>` рядом, как и во всех
остальных actions в шаблоне. Получить SHA тега, не клонируя репозиторий:

```bash
git ls-remote --tags https://github.com/XtReL/devsecops-gatekeeper.git
```

нужная строка — `<SHA>\trefs/tags/v0.1.0` (если тег аннотированный, там
будет ещё и `refs/tags/v0.1.0^{}` — берите SHA из строки с `^{}`: это SHA
коммита, а не объекта тега). Два задания:

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

Это самопроверка владельца: ключ для неё взят из того же репозитория, в
который пишет запись задание `record`, поэтому она подтверждает лишь
внутреннюю согласованность журнала и ключа, а не независимость проверки.
Аудитор проверяет журнал своей копией ключа, полученной от вас напрямую
(шаг 1, а не `.gatekeeper/evidence.pub` из репозитория) — см. выше про
ADR 0001, решение B.

Если проверка прошла — журнал подключён. Дальнейшая ротация ключа
описана в `docs/tasks/rotation.md` и `docs/runbooks/key-rotation.md`.
