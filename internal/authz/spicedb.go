package authz

import (
	"context"
	"log/slog"
	"os"

	authzedpb "github.com/authzed/authzed-go/proto/authzed/api/v1"
	authzed "github.com/authzed/authzed-go/v1"
	"github.com/authzed/grpcutil"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// SpiceDBClient реализует интерфейс handler.AuthZClient
type SpiceDBClient struct {
	client *authzed.Client // Инкапсулируем gRPC-соединение
}

// NewSpiceDBClient инициализирует соединение с графовым движком при загрузке
func NewSpiceDBClient() *SpiceDBClient {
	token := os.Getenv("SPICEDB_TOKEN")
	if token == "" {
		token = "devsecops-secret-key"
	}

	// Устанавливаем gRPC-туннель
	client, err := authzed.NewClient(
		"localhost:50051",
		grpcutil.WithInsecureBearerToken(token),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		slog.Error("[IAM FATAL] Ошибка подключения к SpiceDB", "err", err)
		panic(err) // Fail-Fast: Без Ring 1 запуск шлюза математически бессмысленен
	}

	slog.Info("[BOOT] 🛡️ SpiceDB IAM-клиент успешно инициализирован")

	return &SpiceDBClient{
		client: client,
	}
}

// CheckPermission делает реальный gRPC вызов к базе данных SpiceDB
func (c *SpiceDBClient) CheckPermission(ctx context.Context, subject, permission, resource string) (bool, error) {
	slog.Info("[IAM] Проверка прав в графе", "user", subject, "permission", permission, "repo", resource)

	// Формируем запрос по спецификации Google Zanzibar
	req := &authzedpb.CheckPermissionRequest{
		Consistency: &authzedpb.Consistency{
			// Полная консистентность (защита от гонки данных при параллельных вебхуках)
			Requirement: &authzedpb.Consistency_FullyConsistent{},
		},
		Resource: &authzedpb.ObjectReference{
			ObjectType: "repository", // Берется из вашей iam/schema.zed
			ObjectId:   resource,     // Например: "devsecops-gatekeeper"
		},
		Permission: permission, // Например: "writer"
		Subject: &authzedpb.SubjectReference{
			Object: &authzedpb.ObjectReference{
				ObjectType: "user",  // Берется из вашей iam/schema.zed
				ObjectId:   subject, // Тенант ID, например: "0"
			},
		},
	}

	// Отправляем запрос в графовый движок
	resp, err := c.client.CheckPermission(ctx, req)
	if err != nil {
		slog.Error("[IAM CRITICAL] Ошибка gRPC при проверке прав", "err", err)
		return false, err
	}

	// Транслируем ответ Zanzibar в булево значение
	isAllowed := resp.Permissionship == authzedpb.CheckPermissionResponse_PERMISSIONSHIP_HAS_PERMISSION

	if isAllowed {
		slog.Info("[IAM SUCCESS] ✅ Доступ РАЗРЕШЕН (Связь в графе подтверждена)")
	} else {
		slog.Warn("[IAM REJECT] ⛔ Доступ ЗАПРЕЩЕН (Путь в графе не найден)")
	}

	return isAllowed, nil
}
