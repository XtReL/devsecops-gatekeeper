//go:build ignore

package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"strings"

	// Корневой клиент
	authzed "github.com/authzed/authzed-go/v1"
	// Protobuf-типы (запросы/ответы)
	authzedpb "github.com/authzed/authzed-go/proto/authzed/api/v1"
	"github.com/authzed/grpcutil"
	"github.com/joho/godotenv"

	// Стандартные библиотеки gRPC для Insecure-соединения
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func main() {
	fmt.Println(">>> Инициализация графовой схемы SpiceDB...")

	_ = godotenv.Load(".env")
	fmt.Println(">>> Инициализация графовой схемы SpiceDB...")

	// TrimSpace убирает невидимые символы Windows CRLF из .env
	token := strings.TrimSpace(os.Getenv("SPICEDB_TOKEN"))
	if token == "" {
		log.Fatal("⛔ SPICEDB_TOKEN не задан (см. .env.example)")
	}

	// Чтение вашей ZED-схемы
	schemaBytes, err := os.ReadFile("iam/schema.zed")
	if err != nil {
		log.Fatalf("⛔ Ошибка чтения iam/schema.zed: %v", err)
	}

	// Подключение к локальному узлу SpiceDB
	client, err := authzed.NewClient(
		"localhost:50051",
		grpcutil.WithInsecureBearerToken(token),
		// [FIX] Используем стандартный gRPC Insecure Transport
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		log.Fatalf("⛔ Ошибка подключения gRPC: %v", err)
	}

	// [FIX] Используем пакет authzedpb для структуры запроса
	request := &authzedpb.WriteSchemaRequest{
		Schema: string(schemaBytes),
	}

	_, err = client.WriteSchema(context.Background(), request)
	if err != nil {
		log.Fatalf("⛔ Ошибка записи схемы: %v", err)
	}

	fmt.Println("<<< [IAM SUCCESS] Схема ZED успешно залита в SpiceDB!")
}
