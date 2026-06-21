package auth

import (
	"bytes"
	"context"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"log" // НОВОЕ: Добавлено для вывода отладочной информации
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// GitHubAppClient инкапсулирует логику авторизации. 
// Компоненты ничего не знают о внутреннем устройстве GitHub API.
type GitHubAppClient struct {
	appID      string
	privateKey *rsa.PrivateKey
	httpClient *http.Client
}

// NewGitHubAppClient инициализирует клиент. 
// [SECURITY NOTE]: privateKey должен извлекаться из Vault (in-memory).
func NewGitHubAppClient(appID string, privKey *rsa.PrivateKey) *GitHubAppClient {
	return &GitHubAppClient{
		appID:      appID,
		privateKey: privKey,
		// Защита от исчерпания ресурсов (DoS) при зависании стороннего API
		httpClient: &http.Client{Timeout: 10 * time.Second},
	}
}

// GenerateInstallationToken обменивает JWT на IAT для конкретного тенанта
func (c *GitHubAppClient) GenerateInstallationToken(ctx context.Context, installationID string, permissions map[string]string) (string, error) {
	// --- [MOCK] Заглушка для Фазы 3: Изоляция от реального GitHub API ---
	log.Printf("[DEBUG] Используется локальная заглушка токена для Installation ID: %s", installationID)
	return "mock_iat_token_777_local_dev", nil

	// =====================================================================
	// НИЖЕ РЕАЛЬНЫЙ КОД (ВРЕМЕННО НЕДОСТИЖИМ)
	// Компилятор скомпилирует его, но выполнение сюда никогда не дойдет.
	// Это избавляет нас от необходимости удалять импорты (crypto/rsa, bytes и др.)
	// =====================================================================

	// 1. Генерация JWT (TTL строго 10 минут)
	now := time.Now()
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.RegisteredClaims{
		Issuer:    c.appID,
		IssuedAt:  jwt.NewNumericDate(now.Add(-time.Minute)), // Защита от Clock Skew
		ExpiresAt: jwt.NewNumericDate(now.Add(9 * time.Minute)),
	})

	jwtStr, err := token.SignedString(c.privateKey)
	if err != nil {
		return "", fmt.Errorf("failed to sign jwt: %w", err)
	}

	// 2. Формирование запроса с наименьшими привилегиями
	reqBody, _ := json.Marshal(map[string]interface{}{
		"permissions": permissions,
	})

	url := fmt.Sprintf("https://api.github.com/app/installations/%s/access_tokens", installationID)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewBuffer(reqBody))
	if err != nil {
		return "", err
	}

	req.Header.Set("Authorization", "Bearer "+jwtStr)
	req.Header.Set("Accept", "application/vnd.github.v3+json")

	// 3. Выполнение запроса
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("github api request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		return "", fmt.Errorf("github api returned status: %d", resp.StatusCode)
	}

	// 4. Парсинг ответа
	var result struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("failed to decode response: %w", err)
	}

	return result.Token, nil
}