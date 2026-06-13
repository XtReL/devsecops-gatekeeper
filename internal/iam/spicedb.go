package iam

import (
	"context"
	"fmt"

	pb "github.com/authzed/authzed-go/proto/authzed/api/v1"
	"github.com/authzed/authzed-go/v1"
	"github.com/authzed/grpcutil"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

type SpiceDBClient struct {
	client *authzed.Client
}

// Конструктор: подключаемся к SpiceDB внутри сети Docker
func NewSpiceDBClient(token string) (*SpiceDBClient, error) {
	client, err := authzed.NewClient(
		"gatekeeper-iam:50051", // <--- ИЗМЕНЕНИЕ ЗДЕСЬ (было "localhost:50051")
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpcutil.WithInsecureBearerToken(token),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to SpiceDB: %w", err)
	}
	return &SpiceDBClient{client: client}, nil
}

// CheckPermission спрашивает базу: "Имеет ли право Subject сделать Permission над Resource?"
func (s *SpiceDBClient) CheckPermission(ctx context.Context, resourceType, resourceID, permission, subjectType, subjectID string) (bool, error) {
	resp, err := s.client.PermissionsServiceClient.CheckPermission(ctx, &pb.CheckPermissionRequest{
		Resource: &pb.ObjectReference{
			ObjectType: resourceType,
			ObjectId:   resourceID,
		},
		Permission: permission,
		Subject: &pb.SubjectReference{
			Object: &pb.ObjectReference{
				ObjectType: subjectType,
				ObjectId:   subjectID,
			},
		},
	})

	if err != nil {
		return false, fmt.Errorf("spicedb check error: %w", err)
	}

	// Возвращаем true, только если ответ строго "HAS_PERMISSION"
	return resp.Permissionship == pb.CheckPermissionResponse_PERMISSIONSHIP_HAS_PERMISSION, nil
}
