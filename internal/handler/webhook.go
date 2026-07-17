package handler

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"time"
	// TODO: Исправьте путь импорта на актуальный для вашего проекта
	// "devsecops-gatekeeper/internal/models"
)

// AuthZClient — контракт для БД. Защищает хэндлер от прямой зависимости от SpiceDB.
type AuthZClient interface {
	CheckPermission(ctx context.Context, subject string, permission string, resource string) (bool, error)
}

// WebhookPayload — выборочное извлечение полей из массива вебхука (Selective Unmarshaling).
type WebhookPayload struct {
	Action     string `json:"action"`
	Repository struct {
		FullName string `json:"full_name"`
	} `json:"repository"`
	Sender struct {
		Login string `json:"login"`
	} `json:"sender"`
	PullRequest struct {
		Number int      `json:"number"`
		Head   struct { // [NEW] Состояние ветки
			Sha string `json:"sha"` // [NEW] Криптографический якорь коммита
		} `json:"head"`
	} `json:"pull_request"`
}

type WebhookHandler struct {
	AuthZ AuthZClient
	// Nats NatsClient // TODO: Добавить интерфейс брокера при интеграции
}

func NewWebhookHandler(authz AuthZClient) *WebhookHandler {
	return &WebhookHandler{AuthZ: authz}
}

func (h *WebhookHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Жесткий таймаут
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()

	// Извлекаем только 4 поля (Selective Unmarshaling)
	var payload WebhookPayload
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		slog.Error("webhook_reject: malformed json payload", "error", err)
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	// Отсекаем мусорные эвенты
	if payload.Action != "opened" && payload.Action != "synchronize" {
		w.WriteHeader(http.StatusOK)
		return
	}

	// Формируем запросы к SpiceDB
	resource := "repo:" + payload.Repository.FullName
	subject := "user:" + payload.Sender.Login

	// Проверяем права (Fail Closed)
	hasAccess, err := h.AuthZ.CheckPermission(ctx, subject, "write", resource)
	if err != nil {
		slog.Error("authz_failure: rbac engine error", "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	if !hasAccess {
		slog.Warn("authz_reject: unauthorized", "subject", subject, "resource", resource)
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	slog.Info("authz_success: payload authorized", "subject", subject, "resource", resource)

	// ==========================================
	// [ENFORCEMENT LAYER]: ИНЪЕКЦИЯ ХЭША В ШИНУ
	// ==========================================
	/* Раскомментировать при подключении NATS
	task := models.ScanTask{
		TenantID:  140230661, // TODO: Извлекать динамически из БД или AuthZ
		RepoName:  payload.Repository.FullName,
		CloneURL:  "https://github.com/" + payload.Repository.FullName + ".git",
		CommitSHA: payload.PullRequest.Head.Sha, // [CRITICAL] Передача якоря в воркер
	}

	taskBytes, _ := json.Marshal(task)
	// err = h.Nats.Publish("EVENTS.sast.scan", taskBytes)
	// if err != nil {
	// 	slog.Error("nats_publish_failure", "error", err)
	// 	http.Error(w, "Service Unavailable", http.StatusServiceUnavailable)
	// 	return
	// }
	*/
	// ==========================================

	w.WriteHeader(http.StatusAccepted)
}
