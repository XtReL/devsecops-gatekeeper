// internal/cache/token.go
package cache

import (
	"context"
	"fmt"
	"time"

	"devsecops-gatekeeper/internal/auth" // Замените на реальное имя вашего go-модуля (из go.mod)

	"github.com/go-redis/redis/v8"
)

// TokenProvider управляет жизненным циклом GitHub IAT токенов.
type TokenProvider struct {
	redisClient *redis.Client
	githubApp   *auth.GitHubAppClient
}

func NewTokenProvider(rdb *redis.Client, gh *auth.GitHubAppClient) *TokenProvider {
	return &TokenProvider{
		redisClient: rdb,
		githubApp:   gh,
	}
}

// GetToken возвращает токен. Приоритет: 1. Redis, 2. GitHub API.
func (p *TokenProvider) GetToken(ctx context.Context, tenantID string) (string, error) {
	// Формируем ключ (Hash Tag для будущего шардирования)
	cacheKey := fmt.Sprintf("iat:{%s}", tenantID)

	// 1. Пытаемся получить из кэша
	cachedToken, err := p.redisClient.Get(ctx, cacheKey).Result()
	if err == nil {
		return cachedToken, nil // Возврат за 1 мс (Cache Hit)
	}
	if err != redis.Nil {
		// Redis недоступен (Fail-Closed). Защищаем лимиты GitHub.
		return "", fmt.Errorf("сбой кэша: %w", err)
	}

	// 2. Cache Miss: Генерируем новый токен через GitHub API
	// Запрашиваем минимальные права для сканера (Least Privilege)
	permissions := map[string]string{
		"contents":      "read",
		"pull_requests": "write",
	}
	newToken, err := p.githubApp.GenerateInstallationToken(ctx, tenantID, permissions)
	if err != nil {
		return "", fmt.Errorf("ошибка генерации токена в GitHub: %w", err)
	}

	// 3. Сохраняем в кэш. Токен живет 60 мин, кэшируем на 55 мин.
	// [SECURITY NOTE]: Мы не логируем сам токен при ошибке записи.
	err = p.redisClient.Set(ctx, cacheKey, newToken, 55*time.Minute).Err()
	if err != nil {
		return "", fmt.Errorf("не удалось сохранить токен в кэш: %w", err)
	}

	return newToken, nil
}
