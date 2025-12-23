package grpcserver

import (
	"context"

	controlpb "relay/proto/control"
)

type ControlServiceImpl struct {
	controlpb.UnimplementedControlServiceServer
}

func (s *ControlServiceImpl) RegisterDevice(
	ctx context.Context,
	req *controlpb.RegisterRequest,
) (*controlpb.RegisterResponse, error) {
	return &controlpb.RegisterResponse{Success: true}, nil
}
