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
	"time"
)

const (
	targetURL = "http://localhost:8080/webhook"
	secret    = "whsec_fbf69a17e74e7a6eb9a169f12904a5edcca6aa77d9d39638afc2f6fcb3c39d1a" // Синхронизировано с fallback-значением в main.go
)

func main() {
	// 1. Формирование синтетического Payload (Selective Unmarshaling test)
	payload := []byte(`{
		"action": "opened",
		"repository": {
			"full_name": "XtReL/devsecops-gatekeeper"
		},
		"sender": {
			"login": "XtReL"
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
