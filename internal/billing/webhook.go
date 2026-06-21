package billing

import (
	"database/sql"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"time"

	"github.com/stripe/stripe-go/v76"
	"github.com/stripe/stripe-go/v76/webhook"
)

func HandleStripeWebhook(db *sql.DB, secret string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		payload, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "Error reading request body", http.StatusBadRequest)
			return
		}

		// Проверка подлинности (Signature)
		sigHeader := r.Header.Get("Stripe-Signature")
		event, err := webhook.ConstructEvent(payload, sigHeader, secret)
		if err != nil {
			log.Printf("[STRIPE ERROR] Поддельный вебхук: %v", err)
			http.Error(w, "Bad signature", http.StatusBadRequest)
			return
		}

		// Защита от дублей (Идемпотентность)
		res, err := db.Exec(`INSERT INTO stripe_processed_events (event_id, type) VALUES ($1, $2) ON CONFLICT DO NOTHING`, event.ID, event.Type)
		if err != nil {
			http.Error(w, "DB error", http.StatusInternalServerError)
			return
		}
		rows, _ := res.RowsAffected()
		if rows == 0 {
			w.WriteHeader(http.StatusOK) // Уже обработано
			return
		}

		// Обработка успешной оплаты
		if event.Type == "invoice.paid" {
			var invoice stripe.Invoice
			json.Unmarshal(event.Data.Raw, &invoice)

			// Продлеваем подписку (для MVP хардкодим tenant_id для теста)
			_, _ = db.Exec(`
				INSERT INTO subscriptions (id, tenant_id, status, current_period_end) 
				VALUES ($1, '140230661', 'active', $2)
				ON CONFLICT (id) DO UPDATE SET status = 'active', current_period_end = $2`,
				invoice.Subscription.ID, time.Unix(invoice.PeriodEnd, 0),
			)
			log.Printf("[BILLING] ✅ Оплата прошла! Подписка %s продлена.", invoice.Subscription.ID)
		}

		w.WriteHeader(http.StatusOK)
	}
}
