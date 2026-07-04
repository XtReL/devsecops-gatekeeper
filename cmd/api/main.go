package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"

	"devsecops-gatekeeper/internal/billing"
	"devsecops-gatekeeper/internal/broker"
	"devsecops-gatekeeper/internal/config"
	"devsecops-gatekeeper/internal/iam"
	"devsecops-gatekeeper/internal/middleware"

	"github.com/google/go-github/v60/github" // [SECURITY] Профессиональный движок для валидации HMAC-SHA256 подписей
	"github.com/joho/godotenv"
	_ "github.com/lib/pq"
	"github.com/nats-io/nats.go"
)

type Gateway struct {
	js    nats.JetStreamContext
	spice *iam.SpiceDBClient
	db    *sql.DB
	cfg   config.Config
}

type FindingResponse struct {
	ID         int    `json:"id"`
	RepoName   string `json:"repo_name"`
	RuleID     string `json:"rule_id"`
	FilePath   string `json:"file_path"`
	Secret     string `json:"secret_masked"`
	Status     string `json:"status"`
	DetectedAt string `json:"detected_at"`
}

type UpdateStatusRequest struct {
	FindingID int    `json:"finding_id"`
	Status    string `json:"status"`
}

func main() {
	// 0. ЗАГРУЗКА ПЕРЕМЕННЫХ ОКРУЖЕНИЯ: Самая первая операция, до всех логов и инициализаций
	// [FAIL-SOFT] Если файл не найден (prod-среда) - только warning, но не останавливаем приложение
	envPath := ".env"
	if _, err := os.Stat(envPath); os.IsNotExist(err) {
		// Файл не существует - нормально для production (переменные из внешних источников)
		log.Printf("[BOOT] ⚠️ ВНИМАНИЕ: Файл %s не найден. Используются переменные окружения из системы/контейнера.", envPath)
	} else if err := godotenv.Load(envPath); err != nil {
		// Файл существует, но ошибка при загрузке
		log.Printf("[BOOT] ⚠️ ВНИМАНИЕ: Ошибка загрузки %s: %v. Используются переменные окружения из системы/контейнера.", envPath, err)
	} else {
		log.Printf("[BOOT] ✅ Переменные окружения загружены из %s", envPath)
	}

	log.Println("[BOOT] Запуск API Gateway...")

	cfg := config.Load()
	if err := cfg.Validate(); err != nil {
		log.Fatalf("[FATAL] invalid configuration: %v", err)
	}

	// 1. Подключение к асинхронной шине событий NATS
	nc, err := nats.Connect(cfg.NATSURL)
	if err != nil {
		log.Fatalf("[FATAL] NATS недоступен: %v", err)
	}
	defer nc.Close()

	js, err := nc.JetStream()
	if err != nil {
		log.Fatalf("[FATAL] JetStream не инициализирован: %v", err)
	}

	// 3. Подключение к реляционной СУБД PostgreSQL (Изолированный порт хоста)
	dbConn, err := sql.Open("postgres", cfg.DatabaseURL)
	if err != nil {
		log.Fatalf("[FATAL] Ошибка подключения к БД: %v", err)
	}
	defer dbConn.Close()

	// --- НАЧАЛО ВСТАВЛЯЕМОГО БЛОКА ---
	// 1. Поднимаем IAM-клиента
	spiceEndpoint := os.Getenv("SPICEDB_ENDPOINT")
	if spiceEndpoint == "" {
		spiceEndpoint = "localhost:50051"
	}
	spiceClient, err := iam.NewSpiceDBClient(spiceEndpoint, os.Getenv("SPICEDB_PRESHARED_KEY"))
	if err != nil {
		log.Fatalf("[FATAL] Ошибка подключения к SpiceDB: %v", err)
	}

	// 2. Собираем контроллер Биллинга с внедренными зависимостями
	webhookController := billing.NewWebhookHandler(dbConn, spiceClient)
	// --- КОНЕЦ ВСТАВЛЯЕМОГО БЛОКА ---

	// Теперь spiceClient существует и успешно передастся в Gateway
	gw := &Gateway{js: js, spice: spiceClient, db: dbConn, cfg: cfg}

	// Регистрация детерминированных HTTP-маршрутов
	mux := http.NewServeMux()
	mux.HandleFunc("/webhook", gw.HandleWebhook)
	mux.HandleFunc("/api/v1/findings", gw.HandleGetFindings)
	mux.HandleFunc("/api/v1/findings/status", gw.HandleUpdateStatus)

	// 3. Регистрация эндпоинта
	// Передаем метод контроллера как обработчик HTTP-запросов
	mux.HandleFunc("/api/v1/billing/stripe", webhookController.HandleStripeWebhook)

	log.Printf("[READY] API Gateway развернут на порту %s", cfg.Port)
	if err := http.ListenAndServe(":"+cfg.Port, mux); err != nil {
		log.Fatalf("[FATAL] Сбой сервера: %v", err)
	}
}

// HandleGetFindings осуществляет санкционированную выборку алертов ИБ
func (gw *Gateway) HandleGetFindings(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	user := r.Header.Get("X-User-Login")
	repo := r.URL.Query().Get("repo")

	if err := middleware.ValidateUserLogin(user); err != nil {
		http.Error(w, "invalid X-User-Login", http.StatusBadRequest)
		return
	}
	if err := middleware.ValidateRepoName(repo); err != nil {
		http.Error(w, "invalid repo parameter", http.StatusBadRequest)
		return
	}

	log.Printf("[AUTHZ] Проверка прав: может ли %s читать отчеты %s...", user, repo)

	// 1. Делаем новый вызов, который возвращает чистый bool (hasAccess) и err
	hasAccess, err := gw.spice.CheckPermission(r.Context(), user, repo, "writer")

	// 2. Проверяем ошибку инфраструктуры (сеть, gRPC)
	if err != nil {
		log.Printf("[ERROR] Сбой проверки SpiceDB: %v", err)
		http.Error(w, "Внутренняя ошибка авторизации", http.StatusInternalServerError)
		return
	}

	// 3. Проверяем бизнес-логику (есть ли права?)
	if !hasAccess {
		log.Printf("[SECURITY ALERT] 🛑 Отказ в доступе! Пользователь %s пытался прочитать %s", user, repo)
		http.Error(w, "Доступ запрещен", http.StatusForbidden)
		return
	}

	log.Printf("[DB] Доступ разрешен. Выборка алертов для репозитория: %s", repo)

	// Защита от SQL-инъекций через строго параметризованное связывание переменных
	rows, err := gw.db.Query("SELECT id, repo_name, rule_id, file_path, secret_masked, status, to_char(detected_at, 'YYYY-MM-DD HH24:MI:SS') FROM scan_findings WHERE repo_name = $1 ORDER BY id DESC", repo)
	if err != nil {
		log.Printf("[ERROR] Сбой SQL запроса: %v", err)
		http.Error(w, "Ошибка чтения данных", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var findings []FindingResponse
	for rows.Next() {
		var f FindingResponse
		if err := rows.Scan(&f.ID, &f.RepoName, &f.RuleID, &f.FilePath, &f.Secret, &f.Status, &f.DetectedAt); err != nil {
			log.Printf("[ERROR] Ошибка сканирования строки: %v", err)
			continue
		}
		findings = append(findings, f)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(findings)
}

// HandleWebhook принимает события от VCS систем и инициирует асинхронный пайплайн
func (gw *Gateway) HandleWebhook(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// [SECURITY FIX] 1. АУТЕНТИФИКАЦИЯ (AuthN): Проверка криптографической подписи GitHub
	secret := []byte(gw.cfg.WebhookSecret)
	if len(secret) == 0 {
		log.Println("[FATAL] WEBHOOK_SECRET не задан в конфигурации окружения!")
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	// ValidatePayload предотвращает атаки по времени (Timing Attacks) на сверку хэшей
	payloadBytes, err := github.ValidatePayload(r, secret)
	if err != nil {
		log.Printf("[SECURITY] Поддельный вебхук или некорректная HMAC-подпись: %v", err)
		http.Error(w, "Bad signature", http.StatusForbidden)
		return
	}

	// 2. ДЕКОДИРОВАНИЕ (Парсинг гарантированно подлинных и очищенных байтов)
	var payload struct {
		Installation struct {
			ID int `json:"id"`
		} `json:"installation"`
		Repository struct {
			Name string `json:"name"`
		} `json:"repository"`
		Sender struct {
			Login string `json:"login"`
		} `json:"sender"`
	}

	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		http.Error(w, "Invalid payload", http.StatusBadRequest)
		return
	}

	// 3. АВТОРИЗАЦИЯ (AuthZ): Zero Trust проверка отношений в графе SpiceDB
	// 3. Авторизация (AuthZ):
	// Вставляем ваши переменные из старого пейлоада (скорее всего payload.Sender.Login и payload.Repository.Name)
	hasAccess, err := gw.spice.CheckPermission(r.Context(), payload.Sender.Login, payload.Repository.Name, "writer")

	// Сразу проверяем и системную ошибку, и бизнес-логику (отказ в доступе)
	if err != nil || !hasAccess {
		log.Printf("[SECURITY] Отказ доступа SpiceDB: пользователь %s не верифицирован", payload.Sender.Login)
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	// 4. ФИНАНСОВЫЙ КОНТРОЛЬ: Защита от ресурсоемкого сканирования неоплаченных аккаунтов (Anti-EDoS)
	tenantID := int64(payload.Installation.ID)

	// Проверка активной подписки через пакет billing
	hasActiveSubscription, err := gw.HasActiveSubscription(tenantID)
	if err != nil {
		log.Printf("[BILLING ERROR] Ошибка проверки подписки для tenant %d: %v", tenantID, err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	if !hasActiveSubscription {
		log.Printf("[BILLING] ⛔ Отказ в обслуживании: неоплаченная/отсутствующая подписка для Tenant %d", tenantID)
		http.Error(w, "Payment Required", http.StatusPaymentRequired) // HTTP 402
		return
	}

	// 5. МАРШРУТИЗАЦИЯ ЗАДАЧИ В БРОКЕР
	task := broker.TaskPayload{
		TenantID: fmt.Sprintf("%d", tenantID),
		RepoName: payload.Repository.Name,
	}

	taskData, _ := json.Marshal(task)

	// Динамическое декларирование Stream-конфигурации
	_, _ = gw.js.AddStream(&nats.StreamConfig{
		Name:     "SAST_PIPELINE",
		Subjects: []string{"sast.scan.>"},
	})

	_, err = gw.js.Publish("sast.scan."+fmt.Sprintf("%d", tenantID), taskData)
	if err != nil {
		log.Printf("[ERROR] Ошибка публикации в NATS: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	log.Println("[PIPELINE] Задача успешно принята в очередь сканирования NATS")
	w.WriteHeader(http.StatusAccepted)
	w.Write([]byte(`{"status":"accepted"}`))
}

// HandleUpdateStatus реализует защищенную от BOLA/IDOR модификацию состояний алертов
func (gw *Gateway) HandleUpdateStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req UpdateStatusRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	user := r.Header.Get("X-User-Login")
	if user == "" {
		http.Error(w, "X-User-Login обязателен", http.StatusUnauthorized)
		return
	}

	// 1. ПРЕДОТВРАЩЕНИЕ BOLA: Защитный перехват контекста объекта перед изменением состояния
	var repoName string
	var tenantID string
	err := gw.db.QueryRow("SELECT repo_name, tenant_id FROM scan_findings WHERE id = $1", req.FindingID).Scan(&repoName, &tenantID)
	if err != nil {
		if err == sql.ErrNoRows {
			http.Error(w, "Уязвимость не найдена", http.StatusNotFound)
		} else {
			log.Printf("[ERROR] Ошибка чтения метаданных: %v", err)
			http.Error(w, "Внутренняя ошибка", http.StatusInternalServerError)
		}
		return
	}

	// 2. СВЯЗЫВАНИЕ КОНТЕКСТА С ЗОНОЙ ДОВЕРИЯ (SpiceDB Validation)
	log.Printf("[AUTHZ] Проверка прав на модификацию статуса: %s -> %s (Tenant: %s)", user, repoName, tenantID)
	// 2. СВЯЗЫВАНИЕ КОНТЕКСТА С ЗОНОЙ ДОВЕРИЯ (SpiceDB Validation)
	// Используем наши переменные из функции: user и repoName
	hasAccess, err := gw.spice.CheckPermission(r.Context(), user, repoName, "writer")

	if err != nil || !hasAccess {
		log.Printf("[SECURITY ALERT] 🚨 Попытка несанкционированного изменения статуса от %s для %s", user, repoName)
		http.Error(w, "Доступ запрещен", http.StatusForbidden)
		return
	}

	// 3. ИСПОЛНЕНИЕ КОМАНДЫ (Fail-Secure Execution)
	query := "UPDATE scan_findings SET status = $1 WHERE id = $2"
	_, err = gw.db.Exec(query, req.Status, req.FindingID)
	if err != nil {
		log.Printf("[ERROR] Ошибка обновления статуса в БД: %v", err)
		http.Error(w, "Ошибка обновления", http.StatusInternalServerError)
		return
	}

	log.Printf("[AUDIT] ✅ Пользователь %s изменил статус алерта %d (%s) на %s", user, req.FindingID, repoName, req.Status)
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status":"success"}`))
}

// HasActiveSubscription проверяет наличие активной подписки для тенанта
// Используется для Anti-EDoS защиты: только оплаченные аккаунты могут запускать сканирование
func (gw *Gateway) HasActiveSubscription(tenantID int64) (bool, error) {
	return billing.CheckSubscriptionAccess(gw.db, tenantID)
}
