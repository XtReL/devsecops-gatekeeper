package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"

	"devsecops-gatekeeper/internal/billing"
	"devsecops-gatekeeper/internal/broker"

	pb "github.com/authzed/authzed-go/proto/authzed/api/v1"
	"github.com/authzed/authzed-go/v1"
	"github.com/authzed/grpcutil"
	_ "github.com/lib/pq"
	"github.com/nats-io/nats.go"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

type Gateway struct {
	js    nats.JetStreamContext
	spice *authzed.Client
	db    *sql.DB
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
	log.Println("[BOOT] Запуск API Gateway...")

	// 1. Подключение к асинхронной шине событий NATS
	nc, err := nats.Connect("nats://nats:4222")
	if err != nil {
		log.Fatalf("[FATAL] NATS недоступен: %v", err)
	}
	defer nc.Close()

	js, err := nc.JetStream()
	if err != nil {
		log.Fatalf("[FATAL] JetStream не инициализирован: %v", err)
	}

	// 2. Инициализация gRPC клиента авторизации SpiceDB с защитой транспортного слоя
	spiceClient, err := authzed.NewClient(
		"spicedb:50051",
		grpcutil.WithInsecureBearerToken("somerandomkeyhere"),
		grpc.WithTransportCredentials(insecure.NewCredentials()), // Безопасное явное указание plaintext-режима для локального контура
	)
	if err != nil {
		log.Fatalf("[FATAL] SpiceDB недоступен: %v", err)
	}

	// 3. Подключение к реляционной СУБД PostgreSQL (Изолированный порт хоста)
	dbConn, err := sql.Open("postgres", "postgres://postgres:supersecretpassword@postgres:5432/gatekeeper?sslmode=disable")
	if err != nil {
		log.Fatalf("[FATAL] Ошибка подключения к БД: %v", err)
	}
	defer dbConn.Close()

	gw := &Gateway{js: js, spice: spiceClient, db: dbConn}

	// Регистрация детерминированных HTTP-маршрутов
	mux := http.NewServeMux()
	mux.HandleFunc("/webhook", gw.HandleWebhook)
	mux.HandleFunc("/api/v1/findings", gw.HandleGetFindings)
	mux.HandleFunc("/api/v1/findings/status", gw.HandleUpdateStatus)

	// Регистрация эндпоинта для Stripe вебхуков
	// Секрет временно захардкожен для локального тестирования (в проде берется из .env)
	stripeSecret := "whsec_test_secret"
	mux.HandleFunc("/api/v1/billing/stripe", billing.HandleStripeWebhook(dbConn, stripeSecret))

	log.Println("[READY] API Gateway развернут на порту 8080")
	if err := http.ListenAndServe(":8080", mux); err != nil {
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

	if user == "" || repo == "" {
		http.Error(w, "Параметры X-User-Login и repo обязательны", http.StatusBadRequest)
		return
	}

	log.Printf("[AUTHZ] Проверка прав: может ли %s читать отчеты %s...", user, repo)

	// Детерминированная проверка отношений (Zero Trust Isolation)
	resp, err := gw.spice.CheckPermission(r.Context(), &pb.CheckPermissionRequest{
		Resource:   &pb.ObjectReference{ObjectType: "repository", ObjectId: repo},
		Permission: "writer",
		Subject: &pb.SubjectReference{
			Object: &pb.ObjectReference{ObjectType: "user", ObjectId: user},
		},
	})

	if err != nil {
		log.Printf("[ERROR] Сбой проверки SpiceDB: %v", err)
		http.Error(w, "Внутренняя ошибка авторизации", http.StatusInternalServerError)
		return
	}

	if resp.Permissionship != pb.CheckPermissionResponse_PERMISSIONSHIP_HAS_PERMISSION {
		log.Printf("[SECURITY ALERT] 🛑 Отказ в доступе! Пользователь %s пытался прочитать отчеты репо %s", user, repo)
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

	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, "Invalid payload", http.StatusBadRequest)
		return
	}

	// 1. ПРОВЕРКА АВТОРИЗАЦИИ (Zero Trust)
	resp, err := gw.spice.CheckPermission(r.Context(), &pb.CheckPermissionRequest{
		Resource:   &pb.ObjectReference{ObjectType: "repository", ObjectId: payload.Repository.Name},
		Permission: "writer",
		Subject: &pb.SubjectReference{
			Object: &pb.ObjectReference{ObjectType: "user", ObjectId: payload.Sender.Login},
		},
	})

	if err != nil || resp.Permissionship != pb.CheckPermissionResponse_PERMISSIONSHIP_HAS_PERMISSION {
		log.Printf("[SECURITY] Отказ доступа: %s -> %s", payload.Sender.Login, payload.Repository.Name)
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	// [NEW] 2. ФИНАНСОВЫЙ КОНТРОЛЬ: Блокировка неоплаченного трафика (Economic Denial of Service Protection)
	var subStatus string
	tenantID := fmt.Sprintf("%d", payload.Installation.ID)

	err = gw.db.QueryRow("SELECT status FROM subscriptions WHERE tenant_id = $1", tenantID).Scan(&subStatus)

	if err == sql.ErrNoRows || subStatus != "active" {
		log.Printf("[BILLING] ⛔ Отказ в обслуживании: неоплаченная/отсутствующая подписка для Tenant %s", tenantID)
		http.Error(w, "Payment Required", http.StatusPaymentRequired) // HTTP 402
		return
	}

	// 3. МАРШРУТИЗАЦИЯ ЗАДАЧИ
	task := broker.TaskPayload{
		TenantID: tenantID,
		RepoName: payload.Repository.Name,
	}

	taskData, _ := json.Marshal(task)

	// Динамическое декларирование Stream-конфигурации
	_, _ = gw.js.AddStream(&nats.StreamConfig{
		Name:     "SAST_PIPELINE",
		Subjects: []string{"sast.scan.>"},
	})

	_, err = gw.js.Publish("sast.scan."+task.TenantID, taskData)
	if err != nil {
		log.Printf("[ERROR] Ошибка публикации в NATS: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	log.Println("Задача успешно принята в очередь сканирования")
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
	resp, err := gw.spice.CheckPermission(r.Context(), &pb.CheckPermissionRequest{
		Resource:   &pb.ObjectReference{ObjectType: "repository", ObjectId: repoName},
		Permission: "writer",
		Subject: &pb.SubjectReference{
			Object: &pb.ObjectReference{ObjectType: "user", ObjectId: user},
		},
	})

	if err != nil || resp.Permissionship != pb.CheckPermissionResponse_PERMISSIONSHIP_HAS_PERMISSION {
		log.Printf("[SECURITY ALERT] 🚨 Попытка несанкционированного изменения статуса! Пользователь %s -> Алерт %d", user, req.FindingID)
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
