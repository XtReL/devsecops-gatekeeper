package middleware

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"regexp"
)

var (
	repoNamePattern  = regexp.MustCompile(`^[a-zA-Z0-9._-]{1,100}$`)
	userLoginPattern = regexp.MustCompile(`^[a-zA-Z0-9._-]{1,64}$`)
)

// ValidateRepoName ensures repository names are limited and contain only safe characters.
func ValidateRepoName(value string) error {
	if value == "" {
		return fmt.Errorf("repository name is required")
	}
	if !repoNamePattern.MatchString(value) {
		return fmt.Errorf("repository name contains invalid characters")
	}
	return nil
}

// ValidateUserLogin ensures the user identifier is limited and contains only safe characters.
func ValidateUserLogin(value string) error {
	if value == "" {
		return fmt.Errorf("user login is required")
	}
	if !userLoginPattern.MatchString(value) {
		return fmt.Errorf("user login contains invalid characters")
	}
	return nil
}

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
