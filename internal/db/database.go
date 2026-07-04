package db

import (
	"database/sql"
	"fmt"
	"log"

	_ "github.com/lib/pq" // Анонимный импорт драйвера PostgreSQL
)

type Finding struct {
	TenantID string
	RepoName string
	RuleID   string
	FilePath string
	Secret   string
}

type Database struct {
	db *sql.DB
}

// InitDB подключается к Postgres и автоматически создает таблицы (Auto-Migration)
func InitDB(connStr string) (*Database, error) {
	db, err := sql.Open("postgres", connStr)
	if err != nil {
		return nil, err
	}

	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("база данных недоступна: %w", err)
	}

	// Миграция 1: Таблица для результатов сканирования
	// [SECURITY NOTE]: В столбце secret мы будем хранить только маскированные данные
	scanFindingsQuery := `
	CREATE TABLE IF NOT EXISTS scan_findings (
		id SERIAL PRIMARY KEY,
		tenant_id VARCHAR(50) NOT NULL,
		repo_name VARCHAR(255) NOT NULL,
		rule_id TEXT NOT NULL,
		file_path TEXT NOT NULL,
		secret_masked VARCHAR(255) NOT NULL,
		status VARCHAR(20) DEFAULT 'OPEN',
		detected_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
	);`

	if _, err := db.Exec(scanFindingsQuery); err != nil {
		return nil, fmt.Errorf("ошибка миграции scan_findings: %w", err)
	}

	// Миграция 2: Таблица для подписок (система биллинга)
	// [SECURITY NOTE]: tenant_id используется как ключ для Zero Trust контроля
	subscriptionsQuery := `
	CREATE TABLE IF NOT EXISTS subscriptions (
		tenant_id BIGINT PRIMARY KEY,
		stripe_session_id VARCHAR(255) UNIQUE,
		subscription_id VARCHAR(255),
		status VARCHAR(20) NOT NULL DEFAULT 'active',
		current_period_end TIMESTAMP NOT NULL,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
	);
	CREATE INDEX IF NOT EXISTS idx_subscriptions_status ON subscriptions(status);
	CREATE INDEX IF NOT EXISTS idx_subscriptions_period_end ON subscriptions(current_period_end);`

	if _, err := db.Exec(subscriptionsQuery); err != nil {
		return nil, fmt.Errorf("ошибка миграции subscriptions: %w", err)
	}

	// Миграция 3: Таблица для отслеживания обработанных Stripe событий (идемпотентность)
	// [SECURITY NOTE]: Защита от повторной обработки одного события
	stripeEventsQuery := `
	CREATE TABLE IF NOT EXISTS stripe_processed_events (
		event_id VARCHAR(255) PRIMARY KEY,
		event_type VARCHAR(100) NOT NULL,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
	);
	CREATE INDEX IF NOT EXISTS idx_stripe_events_type ON stripe_processed_events(event_type);
	CREATE INDEX IF NOT EXISTS idx_stripe_events_date ON stripe_processed_events(created_at);`

	if _, err := db.Exec(stripeEventsQuery); err != nil {
		return nil, fmt.Errorf("ошибка миграции stripe_processed_events: %w", err)
	}

	log.Println("[DB] ✅ База данных PostgreSQL успешно инициализирована (все миграции)")
	return &Database{db: db}, nil
}

// SaveFinding сохраняет одну уязвимость в базу
func (d *Database) SaveFinding(f Finding) error {
	query := `
	INSERT INTO scan_findings (tenant_id, repo_name, rule_id, file_path, secret_masked)
	VALUES ($1, $2, $3, $4, $5)`

	_, err := d.db.Exec(query, f.TenantID, f.RepoName, f.RuleID, f.FilePath, f.Secret)
	return err
}
