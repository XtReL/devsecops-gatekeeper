package billing

import (
	"context"
	"database/sql"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"

	"github.com/stripe/stripe-go/v76"
	"github.com/stripe/stripe-go/v76/webhook"
)

// 1. КОНТРАКТ (ИНТЕРФЕЙС)
// Биллинг диктует правила: мне нужен кто-то, кто умеет выдавать права.
// Биллингу неважно, SpiceDB это, AWS IAM или фейковый мок для тестов.
type IAMProvider interface {
	GrantAccess(ctx context.Context, resourceType, resourceID, relation, subjectType, subjectID string) error
}

// 2. СТРУКТУРА КОНТРОЛЛЕРА
// Хранит пулы соединений (Stateful). Уничтожает необходимость прокидывать переменные через аргументы.
type WebhookHandler struct {
	db  *sql.DB
	iam IAMProvider
}

// 3. КОНСТРУКТОР
func NewWebhookHandler(db *sql.DB, iam IAMProvider) *WebhookHandler {
	return &WebhookHandler{
		db:  db,
		iam: iam,
	}
}

// 4. МЕТОД: Главный входной узел вебхука
func (h *WebhookHandler) HandleStripeWebhook(w http.ResponseWriter, r *http.Request) {
	const MaxBodyBytes = int64(65536)
	r.Body = http.MaxBytesReader(w, r.Body, MaxBodyBytes)

	payload, err := io.ReadAll(r.Body)
	if err != nil {
		log.Printf("[STRIPE] Ошибка чтения тела: %v", err)
		http.Error(w, "Bad request", http.StatusServiceUnavailable)
		return
	}

	// Изолируем финансовый секрет от инфраструктурного (GitHub)
	secret := os.Getenv("STRIPE_WEBHOOK_SECRET")

	event, err := webhook.ConstructEventWithOptions(
		payload,
		r.Header.Get("Stripe-Signature"),
		secret,
		webhook.ConstructEventOptions{
			IgnoreAPIVersionMismatch: true,
		},
	)

	// [CRITICAL SEC PATCH] Блокировка прохождения при криптографическом сбое
	if err != nil {
		log.Printf("[STRIPE] ⛔ Отторжение подписи (HMAC): %v", err)
		http.Error(w, "Invalid payload or signature", http.StatusBadRequest)
		return
	}

	// Маршрутизатор стейт-машины
	switch event.Type {
	case "checkout.session.completed":
		// Вызываем внутренний метод
		h.handleCheckoutSessionCompleted(w, event)
	default:
		log.Printf("[STRIPE] Неподдерживаемый тип события: %s", event.Type)
		w.WriteHeader(http.StatusOK) // Fail-Safe: отдаем 200, чтобы Stripe не спамил ретраями
	}
}

// 5. МЕТОД: Бизнес-логика успешной подписки
func (h *WebhookHandler) handleCheckoutSessionCompleted(w http.ResponseWriter, event stripe.Event) {
	var session stripe.CheckoutSession
	if err := json.Unmarshal(event.Data.Raw, &session); err != nil {
		log.Printf("[STRIPE] ⛔ Ошибка парсинга checkout.session: %v", err)
		http.Error(w, "Bad payload", http.StatusBadRequest)
		return
	}

	// 1. Валидация TenantID (Читаем стандартное поле Stripe)
	if session.ClientReferenceID == "" {
		log.Printf("[STRIPE] ⛔ Отсутствует client_reference_id в сессии: %s", session.ID)
		http.Error(w, "Missing metadata", http.StatusBadRequest)
		return
	}

	tenantID, err := strconv.ParseInt(session.ClientReferenceID, 10, 64)
	if err != nil {
		log.Printf("[STRIPE] ⛔ Неверный формат tenant_id: %v", err)
		http.Error(w, "Invalid metadata", http.StatusBadRequest)
		return
	}

	log.Printf("[STRIPE] Обработка сессии %s для tenant %d", session.ID, tenantID)

	// 2. Боевая транзакция БД (Idempotent Upsert)
	// Запись создается или обновляется, если тенант уже существует.
	query := `
		INSERT INTO subscriptions (tenant_id, stripe_session_id, status, current_period_end, created_at, updated_at)
		VALUES ($1, $2, 'active', NOW() + INTERVAL '30 days', NOW(), NOW())
		ON CONFLICT (tenant_id) DO UPDATE SET 
			status = 'active',
			stripe_session_id = EXCLUDED.stripe_session_id,
			current_period_end = EXCLUDED.current_period_end,
			updated_at = NOW()
	`
	_, err = h.db.ExecContext(context.Background(), query, tenantID, session.ID)
	if err != nil {
		log.Printf("[DB] ⛔ Ошибка записи подписки: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	log.Printf("[BILLING] ✅ Подписка аппаратно активирована! Tenant: %d", tenantID)

	// 3. Интеграция с IAM (SpiceDB)
	ctx := context.Background()
	err = h.iam.GrantAccess(ctx, "repository", "demo_repo", "reader", "user", session.ClientReferenceID)
	if err != nil {
		log.Printf("[IAM CRITICAL] Ошибка записи в SpiceDB для tenant %s: %v", session.ClientReferenceID, err)
	} else {
		log.Printf("[IAM SUCCESS] Права reader на demo_repo успешно выданы!")
	}

	// 4. Завершение вебхука
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status":"success"}`))
}
