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

	// Создаем таблицу, если её нет.
	// [SECURITY NOTE]: В столбце secret мы будем хранить только маскированные данные
	query := `
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

	if _, err := db.Exec(query); err != nil {
		return nil, fmt.Errorf("ошибка миграции: %w", err)
	}

	log.Println("[DB] База данных PostgreSQL успешно инициализирована")
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
