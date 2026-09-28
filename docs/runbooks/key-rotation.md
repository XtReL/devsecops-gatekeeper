# Runbook: ротация ключа журнала доказательств

Реализует процедуру ADR 0002 в trust-core (`trust-core/docs/adr/0002-key-rotation.md`,
раздел «Процедура») для журнала этого репозитория (`docs/adr/0001-action-evidence.md`).
Решения ADR не меняет.

Перед началом: `docs/tasks/rotation.md` — единственный источник истины про эпоху
в клиентском репозитории — файл `.gatekeeper/evidence.json`. Ветка и origin
журнала всегда выводятся из номера эпохи (`gatekeeper evidence-target`), не
хранятся отдельно.

Выберите вид ротации:
- **planned** — старый ключ доступен (плановая смена, устройство меняется без потери ключа).
- **unplanned** — старого ключа нет (потеря устройства, подозрение на компрометацию).
  Криптографически неотличимы друг от друга; для unplanned нужен внешний
  доверенный чекпоинт (см. ниже) и решение проверяющего.

Везде ниже `k` — номер новой эпохи (текущая эпоха + 1), `OWNER/REPO` — этот репозиторий.

## 0. Общее для обоих видов

1. Новый ключ — генерируется на устройстве владельца, приватный ключ никогда не
   покидает устройство и не коммитится:

   ```bash
   trustcore keygen -out e<k> -name "github.com/OWNER/REPO/gatekeeper-evidence/v1"
   ```

   Выводит `e<k>.key` (приватный), `e<k>.pub` (публичный), `key id` и `vkey`
   (note-verifier key для свидетелей).

2. Свежий чекаут текущей эпохи (той, что ротируется):

   ```bash
   gatekeeper evidence-target --repo OWNER/REPO   # branch=..., origin=...
   git clone --branch <branch из вывода выше> --single-branch \
     https://github.com/OWNER/REPO.git evidence-current
   ```

## 1. Planned: владелец старого ключа участвует

Точка заморозки — текущее проверенное состояние старой эпохи; генезис
подписан обоими ключами.

```bash
trustcore rotate \
  -from evidence-current \
  -from-origin "$(gatekeeper evidence-target --repo OWNER/REPO | sed -n 's/^origin=//p')" \
  -from-pub .gatekeeper/evidence.pub \
  -from-key /path/to/old.key \
  -new-key e<k>.key \
  -to evidence-e<k> \
  -note "planned rotation: <причина>"
```

Проверьте вывод: `rotation: planned`, `epoch: <k>`, `key id`, `vkey`.

**После успешной ротации уничтожьте старый приватный ключ** на устройстве
владельца (он больше не нужен и не должен переживать ротацию).

## 2. Unplanned: старого ключа нет

Точка заморозки — **внешний доверенный чекпоинт**, не текущее состояние
ветки (его мог редактировать компрометировавший ключ). Возьмите чекпоинт из
копии, которая хранится вне репозитория (у владельца или у аудитора —
`trustcore verify -previous`, файл `checkpoint` из независимого клона/бэкапа
до момента потери/компрометации):

```bash
trustcore rotate \
  -from evidence-current \
  -from-origin "$(gatekeeper evidence-target --repo OWNER/REPO | sed -n 's/^origin=//p')" \
  -from-pub .gatekeeper/evidence.pub \
  -trusted-checkpoint /path/to/trusted-checkpoint \
  -new-key e<k>.key \
  -to evidence-e<k> \
  -note "unplanned rotation: <причина>"
```

Вывод содержит `rotation: unplanned` и предупреждение: «verifiers must
confirm this key id with you out of band and set acceptUnplanned». Запишите
`key id` из вывода — он понадобится проверяющим.

**Уведомление проверяющих вне журнала** (не через сам журнал — старая эпоха
не пишет запись-преемника, п. 6 ADR 0002): для каждого проверяющего лично —
новый origin (`github.com/OWNER/REPO/gatekeeper-evidence/v1/e<k>`), новый
`keyid`, причина ротации, дата. Для публичного репозитория — дополнительно
GitHub Security Advisory с теми же данными. Проверяющий сверяет keyid с
владельцем лично и только после этого добавляет `acceptUnplanned` в свой
манифест (см. ниже) — без этого шага его `verify-chain` откажет.

## 3. Публикация новой эпохи

1. Создайте сиротскую ветку `gatekeeper-evidence-e<k>` из каталога `evidence-e<k>`,
   который создал `trustcore rotate`:

   ```bash
   git clone https://github.com/OWNER/REPO.git evidence-e<k>-push
   cd evidence-e<k>-push
   git checkout --orphan gatekeeper-evidence-e<k>
   git rm -rf . 2>/dev/null || true
   cp -r ../evidence-e<k>/. .
   git add -A
   git commit -m "rotate: epoch <k> genesis"
   git push origin gatekeeper-evidence-e<k>
   cd ..
   ```

2. Секрет CI — **перезаписывается**, старое значение не остаётся:

   ```bash
   gh secret set GATEKEEPER_SIGNING_KEY --env gatekeeper-evidence --repo OWNER/REPO < e<k>.key
   ```

3. Ruleset `evidence-protection`: добавьте вторую явную цель
   `gatekeeper-evidence-e*` (шаблон, не отдельные имена — настраивает
   человек в Settings → Rules; правило то же, что для `gatekeeper-evidence`:
   Restrict deletions + Block force pushes, без required PR/checks).

4. PR в `main` (человек сливает после зелёного CI) с:
   - `.gatekeeper/evidence.json`: `{"epoch": <k>}`;
   - `.gatekeeper/keys/e<k>.pub` — публичный ключ новой эпохи.

   После слияния следующий push на `main` пойдёт в `gatekeeper-evidence-e<k>`:
   `gatekeeper evidence-target` вычисляет это из одного номера эпохи,
   правка кода не нужна.

## 4. Проверка проверяющим

Проверяющий хранит свой манифест отдельно от репозитория (публичные ключи —
только из манифеста, никогда из проверяемого репозитория:
`.gatekeeper/keys/` там только для сверки глазами). Пример манифеста после
одной ротации (эпоха 1 → 2):

```json
{
  "base": "github.com/OWNER/REPO/gatekeeper-evidence/v1",
  "epochs": [
    {"epoch": 1, "log": "ev-e1", "publicKey": "keys/e1.pub", "lastKnownCheckpoint": "cp/e1"},
    {"epoch": 2, "log": "ev-e2", "publicKey": "keys/e2.pub"}
  ]
}
```

Для **unplanned**-ротации у второй эпохи дополнительно `"acceptUnplanned": "<keyid>"`,
и только после личной сверки keyid с владельцем (см. п. 2). `lastKnownCheckpoint`
у уже закрытой эпохи — это её прежний `-previous`, защита от отката всей цепочки
к более ранней истории.

`log` в манифесте — локальные клоны соответствующих веток:

```bash
git clone --branch gatekeeper-evidence --single-branch \
  https://github.com/OWNER/REPO.git ev-e1
git clone --branch gatekeeper-evidence-e2 --single-branch \
  https://github.com/OWNER/REPO.git ev-e2

trustcore verify-chain -manifest manifest.json
```

`OK: every epoch verified and linked by its genesis` — цепочка целиком
проверена: каждая эпоха своим ключом, эпоха 1 закрыта на её замороженном
чекпоинте, генезис эпохи 2 подписан правильными ключами и ссылается на этот
же чекпоинт.

## Учения

Перед боевой ротацией: самотест CI (`scripts/rotation_test.sh`, обе ротации
на bare-репозиториях, часть `scripts/check.sh`) и один ручной прогон этой
процедуры на тестовом репозитории. Боевой журнал переводится на новую эпоху
только по реальной причине (плановая смена устройства или потеря/компрометация
ключа) — не для тренировки.
