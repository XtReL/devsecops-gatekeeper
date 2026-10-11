# ACT-0.1-RECHECK-2, пункт 5: ожидания до запуска

Записано до первого push ветки `test/recheck-2-config`. Объект: `ba73ba0b78ec91a4ac66bdd9ec9956ea8eee87c0`.
Ветка = объект + три файла: этот, `test/recheck-2/epoch2.json` (`{"epoch": 2}`) и
`.github/workflows/recheck-2-config.yml`. Код объекта не меняется.

Workflow срабатывает только на push в `test/recheck-2-config`. Секретов нет, `permissions: contents: read`,
режимов `scan` и `record` нет, в ветку `gatekeeper-evidence` ничего не пишется.

Задание `build`: `uses: ./`, `mode: build` — выход `gatekeeper` не пуст, бинарник выгружается артефактом.

| Задание | `config` | Ожидание шага `mode: target` | `branch` | `origin` |
|---|---|---|---|---|
| `target-unset` | вход не задан | успех | `gatekeeper-evidence` | `github.com/XtReL/devsecops-gatekeeper/gatekeeper-evidence/v1` |
| `target-empty` | `''` | успех, как без входа (`--config` не передаётся) | `gatekeeper-evidence` | `github.com/XtReL/devsecops-gatekeeper/gatekeeper-evidence/v1` |
| `target-epoch2` | `test/recheck-2/epoch2.json` | успех | `gatekeeper-evidence-e2` | `github.com/XtReL/devsecops-gatekeeper/gatekeeper-evidence/v1/e2` |
| `target-missing` | `test/recheck-2/does-not-exist.json` | отказ (`outcome: failure`), в логе `read config test/recheck-2/does-not-exist.json` и `no such file or directory`, нет `does not verify` | пусто | пусто |

В `target-unset` и `target-empty` эпоха 1 берётся из закоммиченного `.gatekeeper/evidence.json` (`{"epoch": 1}`),
ветка «файла нет — эпоха 1» здесь не проверяется.

Каждое задание само проверяет ожидание и падает (`exit 1`) при расхождении. Для `target-missing` шаг `target`
идёт с `continue-on-error: true`, следующий шаг требует `outcome == failure` и пустые выходы; текст причины
проверяется после скачивания лога через API.

Ожидаемый итог прогона: все пять заданий `success`. Другие workflow (`ci.yml`, `gatekeeper.yml`) на этот push
не запускаются: у них `push` только в `main` (`ci.yml` — `main`, `master`), задание `record` в `gatekeeper.yml`
дополнительно ограничено `if:` на push в ветку по умолчанию.
