package github

import (
	"github.com/golang-jwt/jwt/v5"
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Client инкапсулирует логику работы с GitHub App API
type Client struct {
	AppID      string
	PrivateKey *rsa.PrivateKey
	HTTPClient *http.Client
}

// NewClient читает .pem файл с диска и загружает RSA ключ в оперативную память
func NewClient(appID, pemPath string) (*Client, error) {
	// #nosec G304 - Путь к PEM-ключу изолирован в доверенном контуре среды
	pemData, err := os.ReadFile(pemPath)
	if err != nil {
		return nil, fmt.Errorf("ошибка чтения ключа: %v", err)
	}

	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, fmt.Errorf("не найден PEM блок (проверьте формат файла)")
	}

	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("ошибка парсинга RSA ключа: %v", err)
	}

	return &Client{
		AppID:      appID,
		PrivateKey: privateKey,
		HTTPClient: &http.Client{Timeout: 10 * time.Second},
	}, nil
}

// generateJWT создает короткоживущий токен (на 10 минут) для аутентификации самого приложения
func (c *Client) generateJWT() (string, error) {
	now := time.Now()
	claims := jwt.RegisteredClaims{
		// [SECURITY NOTE]: Сдвигаем время на 1 минуту назад для защиты от рассинхрона часов между нашим сервером и GitHub
		IssuedAt: jwt.NewNumericDate(now.Add(-60 * time.Second)),
		// [SECURITY NOTE]: Токен живет строго 10 минут. Если его перехватят, он быстро протухнет.
		ExpiresAt: jwt.NewNumericDate(now.Add(10 * time.Minute)),
		Issuer:    c.AppID,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	return token.SignedString(c.PrivateKey) // Подписание токена нашим закрытым ключом
}

// GetInstallationToken обменивает JWT на эфемерный маркер доступа (IAT) для конкретного репозитория
func (c *Client) GetInstallationToken(installationID string) (string, error) {
	jwtToken, err := c.generateJWT()
	if err != nil {
		return "", fmt.Errorf("сбой генерации JWT: %v", err)
	}

	url := fmt.Sprintf("https://api.github.com/app/installations/%s/access_tokens", installationID)
	req, _ := http.NewRequest(http.MethodPost, url, nil)

	// Представляемся GitHub'у с помощью JWT
	req.Header.Set("Authorization", "Bearer "+jwtToken)
	req.Header.Set("Accept", "application/vnd.github.v3+json")

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("ошибка сети: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("ошибка GitHub API (HTTP %d): %s", resp.StatusCode, string(body))
	}

	var result struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", err
	}

	// Возвращаем токен IAT, с которым можно писать комментарии
	return result.Token, nil
}

// CreateIssue создает новый тикет (Issue) в репозитории с отчетом об уязвимости
func (c *Client) CreateIssue(installationID, owner, repo, title, body string) error {
	// 1. Получаем эфемерный токен доступа (IAT) для конкретного репозитория
	token, err := c.GetInstallationToken(installationID)
	if err != nil {
		return fmt.Errorf("ошибка получения токена: %v", err)
	}

	// 2. Формируем URL GitHub REST API
	url := fmt.Sprintf("https://api.github.com/repos/%s/%s/issues", owner, repo)

	// 3. Собираем JSON
	payload := map[string]string{
		"title": title,
		"body":  body,
	}
	payloadBytes, _ := json.Marshal(payload)

	req, _ := http.NewRequest(http.MethodPost, url, bytes.NewBuffer(payloadBytes))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/vnd.github.v3+json")

	// 4. Отправляем запрос
	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("сбой создания Issue (HTTP %d): %s", resp.StatusCode, string(respBody))
	}

	return nil
}
