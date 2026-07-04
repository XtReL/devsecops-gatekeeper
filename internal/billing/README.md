# DEVSECOPS GATEKEEPER - Billing Package

## Overview

Пакет `internal/billing` обеспечивает обработку платежей и управление подписками через **Stripe** с соблюдением **Security by Default** и **Zero Trust** архитектуры.

## Architecture

### Компоненты

1. **`webhook.go`** — обработчик Stripe вебхуков
   - Верификация криптографической подписи (HMAC-SHA256)
   - Обработка события `checkout.session.completed`
   - Обработка события `invoice.paid`
   - Защита от дублирования обработки событий (идемпотентность)

2. **`subscription.go`** — логика управления подписками
   - Проверка статуса подписки
   - Проверка активности подписки и срока действия
   - Отмена подписки
   - Детерминированные SQL-запросы (защита от SQL-инъекций)

3. **Database Schema**
   - `subscriptions` — таблица подписок тенантов
   - `stripe_processed_events` — таблица для отслеживания обработанных событий

## Security Features

### 1. HMAC-SHA256 Signature Verification
Все входящие вебхуки от Stripe проходят криптографическую верификацию:
```go
event, err := webhook.ConstructEvent(payload, sigHeader, secret)
// Невалидная сигнатура → HTTP 403 Forbidden
```

### 2. Idempotency Protection
Каждое событие Stripe регистрируется в таблице `stripe_processed_events`. 
Повторная обработка одного события игнорируется:
```go
// Проверяем, обработано ли уже это событие
SELECT EXISTS(SELECT 1 FROM stripe_processed_events WHERE event_id = $1)
```

### 3. Parametrized Queries (SQL Injection Prevention)
Все SQL-запросы используют параметризованные переменные (`$1`, `$2`...):
```go
db.Exec("UPDATE subscriptions SET status = $1 WHERE tenant_id = $2", status, tenantID)
// ❌ Text-to-SQL ЗАПРЕЩЕН по архитектуре
```

### 4. Input Validation
- Проверка обязательных полей (tenant_id, session_id, subscription_id)
- Валидация tenant_id как числовой (int64)
- Проверка наличия Stripe-Signature заголовка

### 5. Fail-Secure Design
- Все ошибки логируются с уровнем [STRIPE SECURITY]
- В случае ошибки — откат транзакции (Rollback)
- Краткие сообщения об ошибке в ответе (без утечки информации)

## Integration with main.go

### Webhook Endpoint Registration
```go
mux.HandleFunc("/api/v1/billing/stripe", billing.HandleStripeWebhook(dbConn, stripeSecret))
```

### Usage in API Handlers
```go
// Проверка наличия активной подписки
isActive, err := billing.CheckSubscriptionAccess(gw.db, tenantID)
if !isActive {
    http.Error(w, "Payment Required", http.StatusPaymentRequired) // HTTP 402
    return
}
```

## Event Handling

### checkout.session.completed
Срабатывает при успешном завершении Stripe Checkout сессии:

1. **Извлечение данных**:
   - `session_id` — уникальный идентификатор сессии
   - `metadata.tenant_id` — идентификатор тенанта (определяется при создании сессии)
   - `subscription_id` — опционально, ID подписки в Stripe

2. **Обновление БД**:
   ```sql
   INSERT INTO subscriptions (tenant_id, stripe_session_id, subscription_id, status, current_period_end)
   VALUES (...)
   ON CONFLICT (tenant_id) DO UPDATE SET status = 'active'
   ```

3. **Пример payload в метаданных**:
   ```json
   {
     "metadata": {
       "tenant_id": "12345"
     }
   }
   ```

### invoice.paid
Срабатывает при оплате счета (продление подписки):

1. **Продление на месяц**
2. **Обновление статуса на 'active'**

## Database Schema

### subscriptions
```sql
CREATE TABLE subscriptions (
    tenant_id BIGINT PRIMARY KEY,
    stripe_session_id VARCHAR(255) UNIQUE,
    subscription_id VARCHAR(255),
    status VARCHAR(20) NOT NULL DEFAULT 'active',
    current_period_end TIMESTAMP NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

**Статусы**:
- `active` — подписка активна
- `expired` — подписка истекла
- `canceled` — подписка отменена

### stripe_processed_events
```sql
CREATE TABLE stripe_processed_events (
    event_id VARCHAR(255) PRIMARY KEY,
    event_type VARCHAR(100) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

## Environment Variables

```env
STRIPE_WEBHOOK_SECRET=whsec_xxx...  # Секрет вебхука из dashboard Stripe
DATABASE_URL=postgres://user:pass@host/db  # Connection string PostgreSQL
```

## Testing Stripe Webhook Locally

### 1. Install Stripe CLI
```bash
# Windows (usando choco)
choco install stripe-cli

# macOS
brew install stripe/stripe-cli/stripe

# Linux
https://github.com/stripe/stripe-cli/releases
```

### 2. Authenticate
```bash
stripe login
```

### 3. Forward Events to Local Endpoint
```bash
stripe listen --forward-to http://localhost:8080/api/v1/billing/stripe
```

### 4. Trigger Test Event
```bash
stripe trigger checkout.session.completed --add checkout_session:metadata={tenant_id:12345}
```

## Logging Convention

Все логи используют следующие префиксы:

- `[BILLING]` — информационные сообщения
- `[STRIPE]` — события от Stripe
- `[STRIPE SECURITY]` — события безопасности (попытки с неверной сигнатурой)
- `[STRIPE PARSE ERROR]` — ошибки парсинга JSON
- `[STRIPE VALIDATION]` — ошибки валидации входных данных
- `[STRIPE DB]` — ошибки работы с БД
- `[STRIPE FATAL]` — критические ошибки

## Compliance

✅ **ZERO TRUST**: Каждый платеж привязан к tenant_id и проходит верификацию  
✅ **FAIL-SECURE**: Транзакции откатываются при ошибках  
✅ **SQL Injection Protection**: Все запросы параметризованы  
✅ **HMAC-SHA256**: Все вебхуки верифицируются  
✅ **Idempotency**: События не обрабатываются дважды  

## Related Files

- [cmd/api/main.go](../../cmd/api/main.go) — регистрация webhook handler
- [internal/db/database.go](../db/database.go) — миграции для billing таблиц
- [.github/workflows/prompts/architecture-guidelines.md](../../.github/workflows/prompts/architecture-guidelines.md) — архитектурные требования
