import hmac
import hashlib
import urllib.request
import json
import os

# 1. Читаем секрет из файла .env напрямую
env_secret = "test-local-secret-key-123" # Вставь сюда значение WEBHOOK_SECRET из твоего .env файла
if os.path.exists(".env"):
    with open(".env", "r") as f:
        for line in f:
            if line.startswith("WEBHOOK_SECRET="):
                env_secret = line.strip().split("=", 1)[1]

# 2. Фейковый payload (Вася делает коммит и случайно пушит файл с секретами)
payload = json.dumps({
    "action": "push",
    "repository": {"name": "frontend-app"},
    "sender": {"login": "vasya_developer"},
    "commits": [
        {
            "id": "a1b2c3d4",
            "message": "Update config and fix bugs",
            "added": ["config/database.yml"],   # <-- Этот файл мы будем "сканировать"
            "modified": ["src/main.js"]
        }
    ]
}).encode('utf-8')

# 3. Вычисляем эталонную подпись так же, как это делает настоящий GitHub
signature = hmac.new(
    env_secret.encode('utf-8'),
    payload,
    hashlib.sha256
).hexdigest()

# 4. Формируем заголовки запроса
headers = {
    'Content-Type': 'application/json',
    'X-Hub-Signature-256': f'sha256={signature}',
    'X-GitHub-Delivery': 'dummy-delivery-id-777'
}

# 5. Отправляем POST-запрос на наш Go-шлюз
req = urllib.request.Request('http://localhost:8080/api/v1/webhook', data=payload, headers=headers)

try:
    with urllib.request.urlopen(req) as response:
        print(f"✅ УСПЕХ! Статус: {response.getcode()}")
        print(f"Ответ сервера: {response.read().decode('utf-8')}")
except urllib.error.HTTPError as e:
    print(f"❌ ОШИБКА! Статус: {e.code}")
    print(f"Ответ сервера: {e.read().decode('utf-8')}")