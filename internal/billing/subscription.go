package billing

import (
	"database/sql"
	"log"
	"time"
)

// SubscriptionStatus представляет статус подписки
type SubscriptionStatus string

const (
	StatusActive   SubscriptionStatus = "active"
	StatusExpired  SubscriptionStatus = "expired"
	StatusCanceled SubscriptionStatus = "canceled"
)

// Subscription хранит информацию о подписке тенанта
type Subscription struct {
	TenantID         int64
	StripeSessionID  string
	StripeSubID      string
	Status           SubscriptionStatus
	CurrentPeriodEnd time.Time
	CreatedAt        time.Time
	UpdatedAt        time.Time
}

// GetSubscriptionByTenant получает статус подписки для тенанта (детерминированный запрос)
func GetSubscriptionByTenant(db *sql.DB, tenantID int64) (*Subscription, error) {
	if tenantID <= 0 {
		return nil, sql.ErrNoRows
	}

	sub := &Subscription{TenantID: tenantID}
	err := db.QueryRow(`
		SELECT tenant_id, stripe_session_id, subscription_id, status, current_period_end, created_at, updated_at
		FROM subscriptions
		WHERE tenant_id = $1
	`, tenantID).Scan(
		&sub.TenantID,
		&sub.StripeSessionID,
		&sub.StripeSubID,
		&sub.Status,
		&sub.CurrentPeriodEnd,
		&sub.CreatedAt,
		&sub.UpdatedAt,
	)

	if err != nil {
		return nil, err
	}

	return sub, nil
}

// IsActive проверяет, активна ли подписка и не истекла ли
func (s *Subscription) IsActive() bool {
	if s.Status != StatusActive {
		return false
	}
	return time.Now().Before(s.CurrentPeriodEnd)
}

// CheckSubscriptionAccess проверяет наличие активной подписки (используется в API)
func CheckSubscriptionAccess(db *sql.DB, tenantID int64) (bool, error) {
	var status SubscriptionStatus
	var expiryTime time.Time

	err := db.QueryRow(`
		SELECT status, current_period_end
		FROM subscriptions
		WHERE tenant_id = $1
	`, tenantID).Scan(&status, &expiryTime)

	if err != nil {
		if err == sql.ErrNoRows {
			log.Printf("[BILLING] Подписка не найдена для tenant %d", tenantID)
			return false, nil
		}
		return false, err
	}

	isActive := status == StatusActive && time.Now().Before(expiryTime)
	return isActive, nil
}

// CancelSubscription отменяет подписку (при запросе пользователя или платежном сбое)
func CancelSubscription(db *sql.DB, tenantID int64, reason string) error {
	if tenantID <= 0 {
		return sql.ErrNoRows
	}

	result, err := db.Exec(`
		UPDATE subscriptions
		SET status = $1, updated_at = $2
		WHERE tenant_id = $3 AND status != $1
	`, StatusCanceled, time.Now().UTC(), tenantID)

	if err != nil {
		return err
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}

	if rows > 0 {
		log.Printf("[BILLING] Подписка отменена: tenant=%d, reason=%s", tenantID, reason)
	}

	return nil
}
