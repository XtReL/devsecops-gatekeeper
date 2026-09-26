//go:build ignore

package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

const targetURL = "http://localhost:8080/webhook"

func main() {
	// Секрет вебхука только из окружения (тот же WEBHOOK_SECRET, что у API).
	secret := strings.TrimSpace(os.Getenv("WEBHOOK_SECRET"))
	if secret == "" {
		fmt.Println("sre_alert: WEBHOOK_SECRET is not set (see .env.example)")
		os.Exit(1)
	}

	// 1. Формирование синтетического Payload (Selective Unmarshaling test)
	payload := []byte(`{
		"action": "opened",
		"installation": {
			"id": 1
		},
		"repository": {
			"id": 1,
			"name": "devsecops-gatekeeper",
			"full_name": "XtReL/devsecops-gatekeeper"
		},
		"sender": {
			"login": "XtReL",
			"id": 1
		},
		"pull_request": {
			"number": 42
		},
		"malicious_injection": "this_should_be_ignored"
	}`)

	// 2. Вычисление математически корректной подписи (Bypass Ring 0)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(payload)
	signature := "sha256=" + hex.EncodeToString(mac.Sum(nil))

	// 3. Транспорт (HTTP POST)
	req, err := http.NewRequest("POST", targetURL, bytes.NewBuffer(payload))
	if err != nil {
		fmt.Printf("sre_alert: request compilation failed: %v\n", err)
		return
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Hub-Signature-256", signature)
	req.Header.Set("X-GitHub-Event", "push")

	fmt.Printf(">>> Sending payload to %s\n", targetURL)
	fmt.Printf(">>> Signature: %s\n", signature)

	// 4. Исполнение
	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("sre_alert: connection refused. Is Gatekeeper running? Error: %v\n", err)
		return
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	fmt.Printf("<<< Gatekeeper Status: %s\n", resp.Status)
	fmt.Printf("<<< Gatekeeper Body: %s\n", string(body))
}
