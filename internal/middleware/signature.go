package middleware

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"io"
	"net/http"
)

// VerifyGitHubSignature проверяет подлинность вебхука по HMAC-SHA256
func VerifyGitHubSignature(secret string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		signature := r.Header.Get("X-Hub-Signature-256")
		if signature == "" {
			http.Error(w, "Forbidden: Missing signature header", http.StatusForbidden)
			return
		}

		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "Bad Request: Unable to read body", http.StatusBadRequest)
			return
		}

		// Возвращаем тело запроса обратно, чтобы его мог прочитать следующий обработчик
		r.Body = io.NopCloser(bytes.NewReader(body))

		mac := hmac.New(sha256.New, []byte(secret))
		mac.Write(body)
		expectedMAC := mac.Sum(nil)
		expectedSignature := "sha256=" + hex.EncodeToString(expectedMAC)

		// Защита от timing-атак: сравнение строк за константное время
		if subtle.ConstantTimeCompare([]byte(signature), []byte(expectedSignature)) != 1 {
			http.Error(w, "Forbidden: Signature mismatch", http.StatusForbidden)
			return
		}

		next(w, r)
	}
}
