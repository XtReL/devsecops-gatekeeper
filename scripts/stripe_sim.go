//go:build ignore

package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"strconv"
	"time"
)

const (
	// Эндпоинт шлюза для приема вебхуков Stripe
	targetURL = "http://localhost:8080/api/v1/billing/stripe"
	// Секрет верификации вебхуков (должен совпадать с STRIPE_WEBHOOK_SECRET в .env)
	webhookSecret = "stripe-dev-secret"
)

func main() {
	fmt.Println(">>> Формирование синтетического платежного события Stripe...")

	// Имитируем успешную оплату подписки для Tenant 0 (или укажите ваш TenantID)
	timestamp := time.Now().Unix()
	payload := []byte(fmt.Sprintf(`{
		"id": "evt_test_charge_success",
		"object": "event",
		"type": "checkout.session.completed",
		"data": {
			"object": {
				"id": "cs_test_b12345",
				"client_reference_id": "0",
				"customer": "cus_Hfd8392jnd",
				"subscription": "sub_12345Active",
				"payment_status": "paid"
			}
		}
	}`))

	// Вычисление легитимной сигнатуры Stripe (Паттерн t=timestamp,v1=signature)
	// Stripe подписывает строку: "timestamp.payload"
	signatureHeader := prepareStripeSignature(timestamp, payload, webhookSecret)

	// Формирование HTTP-запроса
	req, err := http.NewRequest("POST", targetURL, bytes.NewBuffer(payload))
	if err != nil {
		fmt.Printf("⛔ Ошибка создания запроса: %v\n", err)
		return
	}

	// Установка обязательных заголовков
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Stripe-Signature", signatureHeader)

	fmt.Printf(">>> Отправка вебхука на %s\n", targetURL)
	fmt.Printf(">>> Stripe-Signature: %s\n", signatureHeader)

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("⛔ Ошибка отправки: %v\n", err)
		return
	}
	defer resp.Body.Close()

	fmt.Printf("<<< Gatekeeper Status: %d %s\n", resp.StatusCode, resp.Status)
}

// prepareStripeSignature собирает заголовок подписи по спецификации Stripe
func prepareStripeSignature(timestamp int64, payload []byte, secret string) string {
	tStr := strconv.FormatInt(timestamp, 10)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(tStr))
	mac.Write([]byte("."))
	mac.Write(payload)
	signature := hex.EncodeToString(mac.Sum(nil))

	return fmt.Sprintf("t=%s,v1=%s", tStr, signature)
}
