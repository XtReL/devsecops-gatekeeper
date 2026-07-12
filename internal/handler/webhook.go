package handler

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"time"
)

// AuthZClient — контракт для БД. Защищает хэндлер от прямой зависимости от SpiceDB.
type AuthZClient interface {
	CheckPermission(ctx context.Context, subject string, permission string, resource string) (bool, error)
}

// WebhookPayload — 4 поля, которые мы извлекаем из всего массива вебхука.
type WebhookPayload struct {
	Action     string `json:"action"`
	Repository struct {
		FullName string `json:"full_name"`
	} `json:"repository"`
	Sender struct {
		Login string `json:"login"`
	} `json:"sender"`
	PullRequest struct {
		Number int `json:"number"`
	} `json:"pull_request"`
}

type WebhookHandler struct {
	AuthZ AuthZClient
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
	w.WriteHeader(http.StatusAccepted)
}