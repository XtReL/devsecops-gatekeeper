package middleware

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"io"
	"log/slog"
	"net/http"
)

const (
	GitHubSignatureHeader = "X-Hub-Signature-256"
	MaxPayloadSize        = 5 << 20
)

func RequireGitHubHMAC(secret string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			signatureHeader := r.Header.Get(GitHubSignatureHeader)
			if signatureHeader == "" {
				slog.Warn("edge_reject: missing signature", "ip", r.RemoteAddr)
				http.Error(w, "Forbidden", http.StatusForbidden)
				return
			}

			bodyReader := io.LimitReader(r.Body, MaxPayloadSize+1)
			body, err := io.ReadAll(bodyReader)
			if err != nil || len(body) > MaxPayloadSize {
				slog.Error("edge_reject: payload exceeds limit", "ip", r.RemoteAddr)
				http.Error(w, "Payload Too Large", http.StatusRequestEntityTooLarge)
				return
			}

			mac := hmac.New(sha256.New, []byte(secret))
			mac.Write(body)
			expectedSignature := "sha256=" + hex.EncodeToString(mac.Sum(nil))

			if subtle.ConstantTimeCompare([]byte(signatureHeader), []byte(expectedSignature)) != 1 {
				slog.Warn("edge_reject: signature mismatch", "ip", r.RemoteAddr)
				http.Error(w, "Forbidden", http.StatusForbidden)
				return
			}

			r.Body = io.NopCloser(bytes.NewBuffer(body))
			next.ServeHTTP(w, r)
		})
	}
}