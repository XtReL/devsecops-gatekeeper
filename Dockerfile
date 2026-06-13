# === ЭТАП 1: Сборка (Builder) ===
FROM golang:alpine AS builder

# Устанавливаем рабочую директорию
WORKDIR /app

# Копируем манифесты зависимостей и скачиваем их
COPY go.mod go.sum ./
RUN go mod download

# Копируем весь остальной исходный код
COPY . .

# Компилируем бинарник. 
# CGO_ENABLED=0 отключает зависимости от C-библиотек ОС, делая файл абсолютно автономным.
RUN CGO_ENABLED=0 GOOS=linux go build -o gatekeeper ./cmd/api/main.go


# === ЭТАП 2: Исполнение (Runtime) ===
FROM alpine:latest

# Устанавливаем корневые сертификаты (нужны для защищенных HTTPS-запросов, если понадобятся)
RUN apk --no-cache add ca-certificates

# SECURITY BY DEFAULT: Создаем непривилегированного пользователя (Non-root user)
RUN addgroup -S gatekeepergroup && adduser -S gatekeeperuser -G gatekeepergroup
USER gatekeeperuser

WORKDIR /home/gatekeeperuser

# Копируем ТОЛЬКО готовый бинарник из первого этапа
COPY --from=builder /app/gatekeeper .

# Указываем, какой порт слушает контейнер
EXPOSE 8080

# Запускаем наш шлюз
CMD ["./gatekeeper"]