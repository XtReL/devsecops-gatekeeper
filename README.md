# DevSecOps Gatekeeper

*Zero Trust secret scanner for GitHub. Findings are stored as SHA-256 fingerprints, never as secret fragments. Signed, verifiable scan evidence is being added via [Trust Core](https://github.com/XtReL/trust-core).*

Сканер утечек секретов для GitHub. Движок обнаружения — [gitleaks](https://github.com/gitleaks/gitleaks) (MIT), закреплённый по версии и контрольной сумме.

## Статус

Ранний прототип. Сейчас работает облачный режим (GitHub App → API → очередь → сканер) для публичных репозиториев. Следующий основной режим — GitHub Action с подписанными аттестациями каждой проверки (этап 3 в плане Trust Core).

## Архитектура облачного режима

| Компонент | Путь | Назначение |
|---|---|---|
| API | `cmd/api` | Приём вебхуков GitHub (проверка HMAC), авторизация в SpiceDB, проверка подписки, постановка задачи в NATS |
| Сканер | `cmd/scanner` | Клонирование, запуск gitleaks, сохранение отпечатков находок, Issue в репозитории |
| Авторизация | `iam/schema.zed`, `internal/iam` | Модель доступа SpiceDB; ресурс — числовой ID репозитория GitHub |
| Биллинг | `internal/billing` | Вебхуки Stripe |

## Запуск локально

```bash
cp .env.example .env        # заполнить значения: openssl rand -hex 32
docker compose config -q    # проверка: без .env команда завершится ошибкой
docker compose up --build
```

## Принципы безопасности

- В репозитории нет секретов, ключей и паролей по умолчанию: всё берётся из `.env`, шаблон — `.env.example`.
- Никаких обходов авторизации в коде: идентификаторы берутся только из подписанного вебхука.
- Находки хранятся как `sha256:<hex>` — ни одного символа секрета в логах и БД.
- GitHub Actions в CI закреплены на полных SHA коммитов.
- Токены доступа не передаются через очередь сообщений.

Лицензия: Apache-2.0.
