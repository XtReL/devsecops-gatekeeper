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

	secret := os.Getenv("WEBHOOK_SECRET")
	event, err := webhook.ConstructEventWithOptions(
		payload,
		r.Header.Get("Stripe-Signature"),
		secret,
		webhook.ConstructEventOptions{
			IgnoreAPIVersionMismatch: true,
		},
	)

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
// Обратите внимание: в аргументах больше нет db *sql.DB. Мы берем его из h.db.
func (h *WebhookHandler) handleCheckoutSessionCompleted(w http.ResponseWriter, event stripe.Event) {
	var session stripe.CheckoutSession
	if err := json.Unmarshal(event.Data.Raw, &session); err != nil {
		log.Printf("[STRIPE PARSE ERROR] Ошибка парсинга checkout.session: %v", err)
		http.Error(w, "Bad payload", http.StatusBadRequest)
		return
	}

	// 1. Валидация метаданных
	tenantStr, ok := session.Metadata["tenant_id"]
	if !ok || tenantStr == "" {
		log.Printf("[STRIPE VALIDATION] Отсутствует tenant_id в метаданных сессии: %s", session.ID)
		http.Error(w, "Missing metadata", http.StatusBadRequest)
		return
	}

	tenantID, err := strconv.ParseInt(tenantStr, 10, 64)
	if err != nil {
		log.Printf("[STRIPE VALIDATION] Неверный формат tenant_id: %v", err)
		http.Error(w, "Invalid metadata", http.StatusBadRequest)
		return
	}

	log.Printf("[STRIPE CHECKOUT] Обработка сессии %s для tenant %d", session.ID, tenantID)

	// 2. Транзакция БД
	// [SECURITY NOTE]: Использование пула соединений h.db.
	// Здесь должен быть ваш реальный SQL-запрос. Пример:
	/*
		_, err = h.db.ExecContext(context.Background(), "INSERT INTO subscriptions (tenant_id, stripe_session) VALUES ($1, $2)", tenantID, session.ID)
		if err != nil {
			log.Printf("[DB ERROR] Ошибка БД: %v", err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}
	*/

	log.Printf("[STRIPE BILLING] ✅ Подписка активирована! Tenant: %d, Сессия: %s", tenantID, session.ID)

	// 3. Интеграция с IAM через интерфейс
	ctx := context.Background()

	// Вызываем gRPC-клиент. Пул соединений находится внутри h.iam.
	err = h.iam.GrantAccess(ctx, "repository", "demo_repo", "reader", "user", tenantStr)
	if err != nil {
		log.Printf("[IAM CRITICAL] Ошибка записи в SpiceDB для tenant %s: %v", tenantStr, err)
		// Мы не отдаем HTTP 500 в Stripe, так как платеж уже прошел. Это инфраструктурный Fail-Secure.
	} else {
		log.Printf("[IAM SUCCESS] Права reader на demo_repo успешно выданы!")
	}

	// 4. Завершение вебхука
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status":"success"}`))
}
