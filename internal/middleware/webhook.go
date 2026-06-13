package middleware

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"io"
	"log"
	"net/http"
	"strings"
)

// WebhookValidator проверяет криптографическую подпись от GitHub
func WebhookValidator(secret []byte) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// 1. Защита памяти: Ограничиваем размер входящего тела (макс 5 MB)
			// Это спасает сервер от падения (OOM), если хакер пришлет гигантский payload
			r.Body = http.MaxBytesReader(w, r.Body, 5*1024*1024)

			bodyBytes, err := io.ReadAll(r.Body)
			if err != nil {
				log.Println("Blocked: Payload too large")
				http.Error(w, "Payload too large", http.StatusRequestEntityTooLarge)
				return
			}

			// Восстанавливаем тело запроса, так как ReadAll его "высушил"
			r.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))

			// 2. Ищем заголовок с подписью от GitHub
			signatureHeader := r.Header.Get("X-Hub-Signature-256")
			if signatureHeader == "" {
				log.Println("Blocked: Missing signature header")
				http.Error(w, "Unauthorized: Missing signature", http.StatusUnauthorized)
				return
			}

			// GitHub присылает подпись в формате "sha256=HEX_ХЭШ..."
			parts := strings.SplitN(signatureHeader, "=", 2)
			if len(parts) != 2 || parts[0] != "sha256" {
				log.Println("Blocked: Invalid signature format")
				http.Error(w, "Unauthorized: Invalid format", http.StatusUnauthorized)
				return
			}

			// 3. Декодируем подпись из текста в байты
			receivedMAC, err := hex.DecodeString(parts[1])
			if err != nil {
				http.Error(w, "Unauthorized: Bad encoding", http.StatusUnauthorized)
				return
			}

			// 4. Вычисляем эталонный хэш из присланного тела с помощью НАШЕГО секрета
			mac := hmac.New(sha256.New, secret)
			mac.Write(bodyBytes)
			expectedMAC := mac.Sum(nil)

			// 5. КРИТИЧЕСКИ ВАЖНО: Защита от тайминг-атак (Constant-Time Compare)
			if subtle.ConstantTimeCompare(receivedMAC, expectedMAC) != 1 {
				log.Println("Blocked: Cryptographic signature mismatch")
				http.Error(w, "Forbidden: Signature mismatch", http.StatusForbidden)
				return
			}

			// Если код дошел сюда — запрос легитимен. Передаем его дальше маршрутизатору.
			next.ServeHTTP(w, r)
		})
	}
}