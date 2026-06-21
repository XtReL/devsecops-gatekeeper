// internal/iam/spicedb.go
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

func NewSpiceDBClient(endpoint, token string) (*SpiceDBClient, error) {
	// [SECURITY NOTE]: insecure используется только для локального docker-compose.
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

// CheckPermission проверяет права с учетом изоляции тенанта
func (s *SpiceDBClient) CheckPermission(ctx context.Context, user, repo string) (bool, error) {
	req := &pb.CheckPermissionRequest{
		Consistency: &pb.Consistency{
			Requirement: &pb.Consistency_FullyConsistent{FullyConsistent: true},
		},
		Resource: &pb.ObjectReference{
			ObjectType: "repository", // Строго совпадает с definition в schema.zed
			ObjectId:   repo,         // Сюда прилетит "core-api"
		},
		Permission: "merge_pr", // Строго совпадает с permission в schema.zed
		Subject: &pb.SubjectReference{
			Object: &pb.ObjectReference{
				ObjectType: "user", // Строго совпадает с definition в schema.zed
				ObjectId:   user,   // Сюда прилетит "madi"
			},
		},
	}

	resp, err := s.client.CheckPermission(ctx, req)
	if err != nil {
		return false, fmt.Errorf("spicedb check failed: %w", err)
	}

	return resp.Permissionship == pb.CheckPermissionResponse_PERMISSIONSHIP_HAS_PERMISSION, nil
}
