package iam

import (
	"context"
	"fmt"
	"log/slog"

	pb "github.com/authzed/authzed-go/proto/authzed/api/v1"
	"github.com/authzed/authzed-go/v1"
	"github.com/authzed/grpcutil"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// SpiceDBClient инкапсулирует пул gRPC-соединений с базой данных авторизации.
type SpiceDBClient struct {
	client *authzed.Client
}

// NewSpiceDBClient инициализирует клиента. Должен вызываться строго один раз при старте шлюза.
func NewSpiceDBClient(endpoint, token string) (*SpiceDBClient, error) {
	// [SECURITY NOTE]: insecure.NewCredentials() используется только для локального docker-compose или защищенного VPC.
	// Для production (public internet) требуется grpc.WithTransportCredentials(credentials.NewTLS(...)).
	client, err := authzed.NewClient(
		endpoint,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpcutil.WithInsecureBearerToken(token),
	)
	if err != nil {
		return nil, err
	}
	return &SpiceDBClient{client: client}, nil
}

// GrantAccess выполняет запись кортежа прав (Relationship Tuple) в граф SpiceDB.
func (s *SpiceDBClient) GrantAccess(ctx context.Context, resourceType, resourceID, relation, subjectType, subjectID string) error {
	req := &pb.WriteRelationshipsRequest{
		Updates: []*pb.RelationshipUpdate{
			{
				Operation: pb.RelationshipUpdate_OPERATION_TOUCH,
				Relationship: &pb.Relationship{
					Resource: &pb.ObjectReference{
						ObjectType: resourceType,
						ObjectId:   resourceID,
					},
					Relation: relation,
					Subject: &pb.SubjectReference{
						Object: &pb.ObjectReference{
							ObjectType: subjectType,
							ObjectId:   subjectID,
						},
					},
				},
			},
		},
	}

	// Используем мультиплексированное соединение из структуры
	_, err := s.client.WriteRelationships(ctx, req)
	if err != nil {
		return fmt.Errorf("ошибка записи кортежа в SpiceDB: %w", err)
	}

	return nil
}

// CheckPermission проверяет наличие прав в графе.
func (s *SpiceDBClient) CheckPermission(ctx context.Context, user, repo, permission string) (bool, error) {
	slog.Info("[IAM] Запрос к оракулу SpiceDB...", "user", user, "repo", repo, "permission", permission)

	// Формируем строгий gRPC-запрос
	req := &pb.CheckPermissionRequest{
		Consistency: &pb.Consistency{
			Requirement: &pb.Consistency_FullyConsistent{FullyConsistent: true},
		},
		Resource: &pb.ObjectReference{
			ObjectType: "repository",
			ObjectId:   repo,
		},
		Permission: permission,
		Subject: &pb.SubjectReference{
			Object: &pb.ObjectReference{
				ObjectType: "user",
				ObjectId:   user,
			},
		},
	}

	// Физический поход в графовую БД
	resp, err := s.client.CheckPermission(ctx, req)
	if err != nil {
		slog.Error("[IAM CRITICAL] Ошибка gRPC при проверке прав", "err", err)
		return false, fmt.Errorf("ошибка проверки прав в SpiceDB: %w", err)
	}

	// Транслируем ответ Zanzibar
	isAllowed := resp.Permissionship == pb.CheckPermissionResponse_PERMISSIONSHIP_HAS_PERMISSION

	if isAllowed {
		slog.Info("[IAM SUCCESS] ✅ Доступ РАЗРЕШЕН (Zanzibar подтвердил связь)")
	} else {
		slog.Warn("[IAM REJECT] ⛔ Доступ ЗАПРЕЩЕН (Связь в графе не найдена)")
	}

	return isAllowed, nil
}

/* === ОРИГИНАЛЬНЫЙ КОД (ЗАКОММЕНТИРОВАН ДЛЯ БАЙПАССА) ===
req := &pb.CheckPermissionRequest{
	Consistency: &pb.Consistency{
		Requirement: &pb.Consistency_FullyConsistent{FullyConsistent: true},
	},
	Resource: &pb.ObjectReference{
		ObjectType: "repository",
		ObjectId:   repo,
	},
	Permission: permission,
	Subject: &pb.SubjectReference{
		Object: &pb.ObjectReference{
			ObjectType: "user",
			ObjectId:   user,
		},
	},
}

resp, err := s.client.CheckPermission(ctx, req)
if err != nil {
	return false, fmt.Errorf("ошибка проверки прав в SpiceDB: %w", err)
}

return resp.Permissionship == pb.CheckPermissionResponse_PERMISSIONSHIP_HAS_PERMISSION, nil
*/
