# BILLING PACKAGE IMPLEMENTATION GUIDE

## Overview

Пакет `internal/billing` реализует полный цикл обработки платежей через Stripe с соблюдением架构 требований:
- ✅ ZERO TRUST (проверка подписи)
- ✅ FAIL-SECURE (транзакции, откат при ошибке)
- ✅ SQL Injection Protection (параметризованные запросы)
- ✅ Idempotency (защита от дублей)

## Quick Start

### 1. Установка зависимостей

```bash
go get github.com/stripe/stripe-go/v76
```

### 2. Конфигурация переменных окружения

```bash
# .env
STRIPE_WEBHOOK_SECRET=whsec_test_...
DATABASE_URL=postgres://user:pass@localhost/gatekeeper
```

### 3. Инициализация БД

При запуске приложения автоматически создаются таблицы:
- `subscriptions`
- `stripe_processed_events`

(см. `internal/db/database.go` — функция `InitDB`)

## API Integration

### Webhook Handler

**Endpoint**: `POST /api/v1/billing/stripe`

**Обработка событий**:

#### 1. `checkout.session.completed`
Срабатывает при успешном завершении платежа в Stripe Checkout.

**Действие**: Активирует подписку для тенанта

**Обязательное поле в metadata**: `tenant_id`

```json
{
  "type": "checkout.session.completed",
  "data": {
    "object": {
      "id": "cs_test_abc123",
      "metadata": {
        "tenant_id": "12345"
      },
      "subscription": "sub_test_xyz"
    }
  }
}
```

#### 2. `invoice.paid`
Срабатывает при оплате счета (продление подписки).

**Действие**: Продляет подписку на месяц

```json
{
  "type": "invoice.paid",
  "data": {
    "object": {
      "id": "in_test_123",
      "subscription": "sub_test_xyz"
    }
  }
}
```

### REST API для проверки подписки

```go
// В Handler'е используй:
hasActive, err := billing.CheckSubscriptionAccess(db, tenantID)
if !hasActive {
    http.Error(w, "Payment Required", http.StatusPaymentRequired) // 402
    return
}
```

## Security Details

### 1. HMAC-SHA256 Signature Verification

Все вебхуки Stripe подписаны с помощью HMAC-SHA256. Верификация:

```go
sigHeader := r.Header.Get("Stripe-Signature")
event, err := webhook.ConstructEvent(payload, sigHeader, secret)
// Если сигнатура невалидна → HTTP 403 Forbidden
```

**Атака на сигнатуру**: Невалидная сигнатура → отклонение + логирование

### 2. Idempotency Protection

Каждое событие сохраняется в таблицу `stripe_processed_events`:

```sql
INSERT INTO stripe_processed_events (event_id, event_type, created_at)
SELECT event_id FROM stripe_processed_events
WHERE event_id = 'evt_test_123'
-- Если уже существует → игнорируется (идемпотентность)
```

**Зачем**: Stripe может отправить одно событие несколько раз.  
**Результат**: Каждое событие обрабатывается ровно один раз.

### 3. SQL Injection Protection

Все запросы используют параметризованные переменные:

```go
// ✅ ПРАВИЛЬНО:
db.Exec("SELECT status FROM subscriptions WHERE tenant_id = $1", tenantID)

// ❌ ЗАПРЕЩЕНО:
db.Exec(fmt.Sprintf("SELECT status FROM subscriptions WHERE tenant_id = %d", tenantID))
```

### 4. Fail-Secure Transactions

При возникновении ошибки все изменения откатываются:

```go
tx, err := db.Begin()
defer tx.Rollback() // Автоматический откат если не был коммит

// ... изменения ...

if err := tx.Commit(); err != nil {
    return err // Изменения не применились
}
```

## Database Schema

### subscriptions

```sql
CREATE TABLE subscriptions (
    tenant_id BIGINT PRIMARY KEY,                  -- Уникальный ID тенанта
    stripe_session_id VARCHAR(255) UNIQUE,        -- Ссылка на Stripe сессию
    subscription_id VARCHAR(255),                 -- Stripe subscription ID
    status VARCHAR(20) NOT NULL DEFAULT 'active', -- active|canceled|expired
    current_period_end TIMESTAMP NOT NULL,        -- Дата истечения подписки
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Индексы для быстрого поиска
CREATE INDEX idx_subscriptions_status ON subscriptions(status);
CREATE INDEX idx_subscriptions_period_end ON subscriptions(current_period_end);
```

### stripe_processed_events

```sql
CREATE TABLE stripe_processed_events (
    event_id VARCHAR(255) PRIMARY KEY,       -- Уникальный ID события от Stripe
    event_type VARCHAR(100) NOT NULL,        -- checkout.session.completed, invoice.paid, и т.д.
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Индексы для аналитики
CREATE INDEX idx_stripe_events_type ON stripe_processed_events(event_type);
CREATE INDEX idx_stripe_events_date ON stripe_processed_events(created_at);
```

## Testing

### Unit Tests

```bash
go test -v ./internal/billing/...
```

**Покрытие тестами**:
- ✅ Валидация tenant_id
- ✅ Проверка наличия сигнатуры
- ✅ Парсинг JSON payload
- ✅ Проверка активности подписки
- ❌ Криптография (используй Stripe Test Keys)

### Integration Tests (локальное тестирование)

#### 1. Установи Stripe CLI

```bash
# Windows
choco install stripe-cli

# macOS
brew install stripe/stripe-cli/stripe

# Linux
curl https://files.stripe.com/stripe-cli/releases/linux/v43.0.0/stripe_linux_x86_64.tar.gz -o stripe_linux_x86_64.tar.gz
tar -zxvf stripe_linux_x86_64.tar.gz
sudo ./stripe /usr/local/bin/stripe
```

#### 2. Аутентифицируйся в Stripe

```bash
stripe login
```

#### 3. Запусти приложение (в окне 1)

```bash
go run cmd/api/main.go
```

#### 4. Пробросьте события в локальное приложение (в окне 2)

```bash
# Слушаем события и пробрасываем на localhost
stripe listen --forward-to http://localhost:8080/api/v1/billing/stripe

# В отдельном окне: отправляем тестовое событие
stripe trigger checkout.session.completed --add checkout_session:metadata={tenant_id:12345}
```

#### 5. Проверьте логи

```
[STRIPE CHECKOUT] Обработка сессии cs_... для tenant 12345
[STRIPE BILLING] ✅ Подписка активирована! Tenant: 12345, Сессия: cs_...
```

## Error Handling

### Возможные ошибки и их обработка

| Ошибка | HTTP Code | Что произошло | Решение |
|--------|-----------|---------------|---------|
| `Bad signature` | 403 | Невалидная сигнатура | Проверь `STRIPE_WEBHOOK_SECRET` |
| `Event already processed` | 200 | Событие уже обработано | Нормально (идемпотентность) |
| `Missing tenant_id` | 400 | Нет tenant_id в metadata | Проверь параметры Checkout сессии |
| `Invalid tenant_id` | 400 | tenant_id не число | Передай число, а не строку |
| `DB error` | 500 | Ошибка БД | Проверь подключение к PostgreSQL |

### Логирование

```
[BILLING]           - Информационные сообщения
[STRIPE]            - События от Stripe
[STRIPE SECURITY]   - События безопасности (попытки взлома)
[STRIPE VALIDATION] - Ошибки валидации
[STRIPE DB]         - Ошибки работы с БД
[STRIPE FATAL]      - Критические ошибки
```

## Production Deployment

### 1. Замените Test ключи на Live ключи

```bash
# .env (production)
STRIPE_WEBHOOK_SECRET=whsec_live_...
STRIPE_SECRET_KEY=sk_live_...
STRIPE_PUBLISHABLE_KEY=pk_live_...
```

### 2. Настройте Stripe Webhooks в Dashboard

**URL**: `https://yourdomain.com/api/v1/billing/stripe`

**Events to send**: 
- `checkout.session.completed`
- `invoice.paid`
- `invoice.payment_failed` (опционально, для отмены подписки)

### 3. Используйте HTTPS для вебхуков

Stripe требует HTTPS для production. Используйте:
- Reverse proxy (nginx, caddy)
- Let's Encrypt для SSL сертификата
- Или AWS ALB с SSL termination

### 4. Мониторинг

Настройте алерты для:
- Ошибок обработки вебхуков: `[STRIPE SECURITY]`, `[STRIPE DB]`
- Просрочки подписок (cron job для обновления статуса)
- Платежных сбоев: `invoice.payment_failed`

## Related Docs

- [README.md](./README.md) — архитектура и особенности
- [webhook.go](./webhook.go) — обработчик вебхуков
- [subscription.go](./subscription.go) — логика подписок
- [../db/database.go](../db/database.go) — миграции БД
- [../../cmd/api/main.go](../../cmd/api/main.go) — регистрация обработчика
- [architecture-guidelines.md](../../.github/workflows/prompts/architecture-guidelines.md) — архитектурные требования

## FAQ

**Q: Почему tenant_id это BIGINT, а не STRING?**  
A: BIGINT быстрее для индексирования и сравнений. Stripe Installation ID это число.

**Q: Что если дважды отправить один вебхук?**  
A: Второй раз будет игнорирован (идемпотентность через stripe_processed_events).

**Q: Как отменить подписку?**  
A: Вызови `billing.CancelSubscription(db, tenantID, "reason")`.

**Q: Поддерживаются ли разные виды подписок (free, pro, enterprise)?**  
A: Текущая реализация единая для всех. Для разных уровней расширь metadata.

**Q: Можно ли использовать Stripe в тестовом режиме параллельно с prod?**  
A: Да, но используй разные `STRIPE_WEBHOOK_SECRET` для каждого окружения.
