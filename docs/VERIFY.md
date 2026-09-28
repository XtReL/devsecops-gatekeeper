# Независимая проверка журнала доказательств

Инструкция для постороннего проверяющего: у вас нет доступа к секретам
владельца репозитория, только публичные ветки на GitHub. Нужны **Go** (для
сборки `trustcore` и, при желании воспроизведения, `gatekeeper`) и **git**.
Все команды — обычный шелл (bash, zsh, PowerShell — где написано иначе,
указано отдельно).

Решения, которые эта инструкция не меняет и не оспаривает, зафиксированы в
[`docs/adr/0001-action-evidence.md`](adr/0001-action-evidence.md) (модель
угроз, формат журнала) и [`docs/tasks/rotation.md`](tasks/rotation.md)
(эпохи). Если что-то здесь разойдётся с ADR — доверяйте ADR и сообщите об
этом (раздел «Как сообщить результат» ниже).

## Что доказывает проверка, а что нет

Дословно модель угроз из ADR 0001:

> Подпись удостоверяет, что владелец ключа заявил этот результат для этого
> коммита с этой версией сканера и правил, и что заявление не изменено
> задним числом — при условии, что копии чекпоинтов хранятся вне
> репозитория. Правдивость заявления проверяется воспроизведением: сканер
> детерминирован, а в аттестации закреплено всё, что нужно для повтора.
> Подпись не удостоверяет, что сам запуск не сфабрикован владельцем
> ключа; независимое подтверждение запуска — OIDC-свидетель на этапе 6.

Разворачивая это в проверяемые пункты:

**Доказывает** (при выполнении шагов ниже):
- запись в журнале не изменена и не удалена задним числом — целостность
  ветки журнала защищена подписанным чекпоинтом и структурой Меркла;
  подмена одной записи меняет корень, который проверяет подпись;
- запись действительно подписана ключом, чей публичный аналог вы держите
  в руках (откуда его брать — см. «Публичный ключ» ниже);
- содержимое заявления (коммит, версия сканера, версия правил, результат
  сканирования, находки) — то самое, что было подписано в момент записи;
- если вы воспроизвели сканирование (раздел «Воспроизведение») — результат
  сканирования на заявленном коммите действительно соответствует
  зафиксированному в аттестации `sha256`.

**Не доказывает:**
- что владелец ключа не сфабриковал сам запуск (запустил `gatekeeper
  record` вручную с произвольными входными данными, а не из настоящего CI)
  — до этапа 6 (независимая контрподпись через OIDC-свидетеля) это не
  проверяется криптографически;
- что администратор репозитория не мог удалить или переписать историю
  ветки журнала целиком, если вы проверяете **только** текущее состояние
  ветки на GitHub без внешней копии чекпоинта (см. «Сохраняйте копию
  чекпоинта» ниже) — гарантию даёт не ruleset ветки, а независимые копии
  чекпоинтов у сторон вроде вас;
- что найденные (или не найденные) секреты действительно валидны или
  невалидны — только то, что заявленный сканер на заявленной версии правил
  заявил этот результат для этого коммита.

## Установка `trustcore` v0.2.0

```bash
go install github.com/XtReL/trust-core/cmd/trustcore@v0.2.0
trustcore -h   # без флагов печатает список команд
```

## Публичный ключ

Два источника, не взаимозаменяемые:

- **Правильно** — получить ключ (или `key id`/`vkey` для сверки) от
  владельца репозитория напрямую, вне GitHub (сообщением, лично, любым
  каналом, независимым от репозитория). Это единственный способ, который
  не зависит от доверия к самому репозиторию: тот, кто может писать в
  ветку журнала, теоретически мог бы подменить и запись, и файл ключа в
  репозитории одновременно.
- **Для знакомства с форматом**, а не для настоящей проверки — публичный
  ключ можно взять из `.gatekeeper/evidence.pub` в ветке `main`
  проверяемого репозитория:

  ```bash
  curl -fsSL -o evidence.pub \
    https://raw.githubusercontent.com/OWNER/REPO/main/.gatekeeper/evidence.pub
  ```

  Так проверка подтверждает только внутреннюю согласованность репозитория
  (ADR 0001, решение B, тот же оговор, что в `docs/onboarding.md`, шаг 7):
  ключ и запись взяты из одного и того же места, которым управляет один и
  тот же владелец. Не выдавайте результат такой проверки за независимую.

## Клонирование ветки журнала

**Обязательно** с `-c core.autocrlf=false` — ветка журнала уже несёт
`.gitattributes` (`* -text`), который сам по себе отключает перевод
строк при клонировании, но если у вас настроен `core.autocrlf=true`
глобально и по какой-то причине проверяемая ветка **старой** записи не
содержит `.gitattributes` (журнал, созданный до этого исправления), явный
`-c core.autocrlf=false` — дополнительная защита от «malformed note» на
`checkpoint`, который иначе перестаёт совпадать с подписанными байтами:

```bash
git clone -c core.autocrlf=false \
  --branch gatekeeper-evidence --single-branch \
  https://github.com/OWNER/REPO.git evidence-check
```

Для эпохи `k ≥ 2` (после ротации, `docs/tasks/rotation.md`) — ветка
`gatekeeper-evidence-e<k>`, публичный ключ — `.gatekeeper/keys/e<k>.pub` в
`main` (та же оговорка про «для знакомства», что выше).

## Если вы на Windows

`core.autocrlf=true` — настройка по умолчанию на Windows, поэтому все
`git clone` в этой инструкции явно несут `-c core.autocrlf=false`: без
него `LF` в клонированных файлах превращается в `CRLF`, сканер или
`trustcore` видят другие байты, чем были подписаны, и проверка либо
падает, либо (хуже) для репозитория с находками молча даёт `result.json`,
не совпадающий с заверенным `sha256` (см. «Клонирование ветки журнала» и
раздел «Воспроизведение» выше).

Из этого — два практических следствия:

- Если каталог уже склонирован **без** `-c core.autocrlf=false`, править
  его на месте (например, `git config core.autocrlf false` внутри уже
  созданного `.git`) не поможет: файлы рабочей копии уже переписаны в
  `CRLF` при checkout. Удалите каталог и склонируйте заново с флагом —
  других надёжных вариантов нет.
- Ошибка `trustcore verify` вида «malformed note» почти всегда означает
  именно это: `checkpoint` (или запись) были перезаписаны в `CRLF` при
  клонировании и байты перестали совпадать с подписанными. Это не
  повреждение журнала и не признак подделки — это первое, что стоит
  проверить, прежде чем подозревать целостность записи.

## Проверка

```bash
trustcore verify \
  -log evidence-check \
  -origin "github.com/OWNER/REPO/gatekeeper-evidence/v1" \
  -log-pub evidence.pub \
  -attester-pub evidence.pub
```

Ожидаемый вывод при исправном журнале:

```
log:       github.com/OWNER/REPO/gatekeeper-evidence/v1
size:      N
root:      <base64 корня Меркла>
OK: checkpoint signature, Merkle root and all entry signatures verified
```

`-log-pub` и `-attester-pub` — один и тот же файл (ADR 0001, решение B: в
режиме Action один ключ подписывает и записи, и чекпоинты). `-origin`
необязателен, но настоятельно рекомендуется: без него `trustcore` не
проверит, что клонированная ветка — действительно та, что заявлена (имя
ветки на GitHub ничем не гарантировано, `origin` в подписанном чекпоинте
— гарантировано).

## Сохраняйте копию чекпоинта

Журнал только дописывается (append-only) — ADR 0001 требует независимые
копии чекпоинтов именно поэтому: без них проверка подтверждает лишь
*текущее* состояние ветки, а не то, что оно не было переписано с нуля.
После каждой проверки:

```bash
cp evidence-check/checkpoint my-checkpoints/OWNER-REPO-$(date +%Y%m%d).checkpoint
```

При следующей проверке передайте сохранённый файл через `-previous` —
`trustcore` подтвердит, что первые N записей нового чекпоинта совпадают с
тем, что вы видели раньше (история не переписана задним числом):

```bash
trustcore verify \
  -log evidence-check \
  -origin "github.com/OWNER/REPO/gatekeeper-evidence/v1" \
  -log-pub evidence.pub \
  -attester-pub evidence.pub \
  -previous my-checkpoints/OWNER-REPO-20260901.checkpoint
```

Успешный вывод добавляет строку `history: first N entries match the
previous checkpoint`.

## Как раскодировать запись

Каждая запись в `entries/00000000000000000000.json` и далее — конверт DSSE:
поле `payload` — стандартный base64 от JSON-документа in-toto Statement.
Расшифровка без специального инструмента:

```bash
jq -r '.payload' evidence-check/entries/00000000000000000000.json \
  | base64 -d | jq .
```

На что смотреть в результате:

| Путь в JSON | Что это | Пример |
|---|---|---|
| `subject[0].digest.gitCommit` | коммит, для которого сделано заявление | `dfb3bcc3…` |
| `predicateType` | тип предиката (у gatekeeper всегда test-result) | `https://in-toto.io/attestation/test-result/v0.1` |
| `predicate.result` | `PASSED` / `FAILED` | `PASSED` |
| `predicate.configuration[0].digest.sha256` | sha256 `result.json` сканирования — сверяется при воспроизведении | `b12037b5…` |
| `predicate.configuration[0].annotations.gatekeeperVersion` | версия `gatekeeper`, использованная в CI | `0.1.0` |
| `predicate.configuration[0].annotations.gitleaksVersion` | версия движка gitleaks | `v8.30.1` |
| `predicate.configuration[0].annotations.rulesDigest` | sha256 встроенных правил gitleaks | `sha256:e163e53b…` |
| `predicate.configuration[0].annotations.reproduce` | точная команда повтора | `git checkout … && gatekeeper scan …` |
| `predicate.configuration[0].annotations.findings` | находки (только `rule`/`file`/`fingerprint`, без значений секретов) | `[]` |
| `predicate.url` | ссылка на запуск CI, где сделана запись | `https://github.com/…/actions/runs/…` |

`jq` не обязателен — то же самое можно сделать `python3 -c "import
json,base64,sys; print(json.dumps(json.loads(base64.b64decode(json.load(open(sys.argv[1]))['payload'])), indent=2))" entries/….json`.

## Воспроизведение

Подпись без воспроизведения удостоверяет только заявление, а не его
правдивость (см. «Что доказывает проверка» выше). Чтобы проверить
правдивость:

1. Соберите `gatekeeper` из тега, которым была сделана запись
   (`gatekeeperVersion` из аннотации выше; релизы —
   `git ls-remote --tags https://github.com/XtReL/devsecops-gatekeeper.git`):

   ```bash
   git clone -c core.autocrlf=false \
     https://github.com/XtReL/devsecops-gatekeeper.git gatekeeper-src
   cd gatekeeper-src
   git checkout v0.1.0
   GOFLAGS=-mod=readonly go build -o ../gatekeeper ./cmd/gatekeeper
   cd ..
   ```

2. Отдельно клонируйте **проверяемый** репозиторий (тот, чей коммит
   заявлен в `subject[0].digest.gitCommit`, не devsecops-gatekeeper — если
   вы проверяете чужой журнал, это будет другой репозиторий) и перейдите на
   этот коммит. Здесь `-c core.autocrlf=false` важен особо: если у
   проверяемого репозитория на заявленном коммите нет `.gitattributes` с
   `* -text` (это отдельный репозиторий со своей историей, gatekeeper его
   не контролирует), Windows с `core.autocrlf=true` по умолчанию превратит
   `LF` в `CRLF` при клонировании — сканер увидит другие байты, чем CI на
   Linux, и `result.json` разойдётся с `sha256`, зафиксированным в
   аттестации, даже если сама проверка записи (раздел «Проверка» выше)
   прошла успешно:

   ```bash
   git clone -c core.autocrlf=false https://github.com/OWNER/REPO.git checked-out
   cd checked-out
   git checkout <gitCommit из шага «Как раскодировать запись»>
   ```

3. Прогоните тот же сканер и сравните sha256 с `configuration[0].digest.sha256`:

   ```bash
   ../gatekeeper scan --source . --out /tmp/result.json
   sha256sum /tmp/result.json
   ```

   Совпадение — сканирование воспроизводимо: тот же коммит с тем же
   сканером и теми же правилами детерминированно даёт тот же результат,
   что был подписан.

## Примеры на живых журналах

Оба репозитория публичные, эти команды можно выполнить прямо сейчас.

### `devsecops-gatekeeper`

```bash
git clone -c core.autocrlf=false --branch gatekeeper-evidence --single-branch \
  https://github.com/XtReL/devsecops-gatekeeper.git dg-evidence
curl -fsSL -o dg-evidence.pub \
  https://raw.githubusercontent.com/XtReL/devsecops-gatekeeper/main/.gatekeeper/evidence.pub

trustcore verify -log dg-evidence \
  -origin "github.com/XtReL/devsecops-gatekeeper/gatekeeper-evidence/v1" \
  -log-pub dg-evidence.pub -attester-pub dg-evidence.pub
```

```
log:       github.com/XtReL/devsecops-gatekeeper/gatekeeper-evidence/v1
size:      7
root:      NnJkL0GCF2yhoCXDrAaVBMg18b7sJWSpZe5wm2fj6/o=
OK: checkpoint signature, Merkle root and all entry signatures verified
```

(`size` растёт с каждым push в `main` — у вас будет больше записей, чем
здесь; это ожидаемо.)

### `trust-core`

```bash
git clone -c core.autocrlf=false --branch gatekeeper-evidence --single-branch \
  https://github.com/XtReL/trust-core.git tc-evidence
curl -fsSL -o tc-evidence.pub \
  https://raw.githubusercontent.com/XtReL/trust-core/main/.gatekeeper/evidence.pub

trustcore verify -log tc-evidence \
  -origin "github.com/XtReL/trust-core/gatekeeper-evidence/v1" \
  -log-pub tc-evidence.pub -attester-pub tc-evidence.pub
```

```
log:       github.com/XtReL/trust-core/gatekeeper-evidence/v1
size:      1
root:      dVggObDJ69ZoVxLwn1FcE6Y2zi4YwArROizCsDTstAE=
OK: checkpoint signature, Merkle root and all entry signatures verified
```

## Как сообщить результат

Через шаблон issue [`.github/ISSUE_TEMPLATE/verification-report.md`](../.github/ISSUE_TEMPLATE/verification-report.md)
в репозитории, который вы проверяли: **New issue** → «Verification report».
Заполните журнал, размер и корень из вывода `trustcore verify`, дату, ОС и
версию Go, и опишите, что не получилось или было непонятно, даже если
итог — «всё сошлось»: это тоже полезный сигнал.
