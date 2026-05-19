package grpcserver

import (
	"context"
	"errors"
	"fmt"
	"strings"

	controlpb "relay/proto/control"
	tunnelpb "relay/proto/tunnel"
	"relay/registry"
	"relay/storage"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type ControlServiceImpl struct {
	controlpb.UnimplementedControlServiceServer
	Store *storage.Repository
}

func (s *ControlServiceImpl) RegisterDevice(
	ctx context.Context,
	req *controlpb.RegisterRequest,
) (*controlpb.RegisterResponse, error) {
	fingerprint, err := storage.ClientCertFingerprint(ctx)
	if err != nil {
		return nil, status.Errorf(codes.Unauthenticated, "client certificate is required: %v", err)
	}

	_, domains, err := s.Store.RegisterDeviceWithDomains(ctx, fingerprint, req.GetDomains())
	if err != nil {
		return nil, storageError("register device", err)
	}

	return &controlpb.RegisterResponse{
		Success: true,
		Message: fmt.Sprintf("registered %d domain(s)", len(domains)),
	}, nil
}

func (s *ControlServiceImpl) ListDomains(
	ctx context.Context,
	req *controlpb.ListDomainsRequest,
) (*controlpb.ListDomainsResponse, error) {
	fingerprint, err := storage.ClientCertFingerprint(ctx)
	if err != nil {
		return nil, status.Errorf(codes.Unauthenticated, "client certificate is required: %v", err)
	}

	domains, err := s.Store.ListDomainsForFingerprint(ctx, fingerprint)
	if err != nil {
		return nil, storageError("list domains", err)
	}

	out := make([]string, 0, len(domains))
	for _, domain := range domains {
		out = append(out, domain.FQDN)
	}
	return &controlpb.ListDomainsResponse{Domains: out}, nil
}

func (s *ControlServiceImpl) UnregisterDomain(
	ctx context.Context,
	req *controlpb.UnregisterDomainRequest,
) (*controlpb.UnregisterDomainResponse, error) {
	fingerprint, err := storage.ClientCertFingerprint(ctx)
	if err != nil {
		return nil, status.Errorf(codes.Unauthenticated, "client certificate is required: %v", err)
	}

	domain, err := storage.NormalizeDomain(req.GetDomain())
	if err != nil {
		return nil, storageError("unregister domain", err)
	}

	deleted, err := s.Store.DeleteOwnedDomain(ctx, fingerprint, domain)
	if err != nil {
		return nil, storageError("unregister domain", err)
	}
	if deleted {
		if dev, active := registry.Global.Unbind(domain); active && dev != nil {
			dev.SendFrame(&tunnelpb.Frame{
				Type:    tunnelpb.FrameType_FRAME_BIND_REJECTED,
				Payload: []byte(domain),
			})
		}
	}

	return &controlpb.UnregisterDomainResponse{Success: deleted}, nil
}

func storageError(operation string, err error) error {
	switch {
	case errors.Is(err, storage.ErrFingerprintInvalid):
		return status.Errorf(codes.InvalidArgument, "%s: invalid certificate fingerprint", operation)
	case errors.Is(err, storage.ErrDomainInvalid):
		return status.Errorf(codes.InvalidArgument, "%s: invalid domain", operation)
	case errors.Is(err, storage.ErrDomainAlreadyUsed):
		return status.Errorf(codes.AlreadyExists, "%s: domain already belongs to another device", operation)
	case errors.Is(err, storage.ErrDeviceRevoked):
		return status.Errorf(codes.PermissionDenied, "%s: device is revoked", operation)
	case errors.Is(err, storage.ErrDomainNotOwned):
		return status.Errorf(codes.PermissionDenied, "%s: domain is not owned by this device", operation)
	case errors.Is(err, storage.ErrDomainDisabled):
		return status.Errorf(codes.PermissionDenied, "%s: domain is disabled", operation)
	default:
		return status.Errorf(codes.Internal, "%s: %s", operation, strings.TrimSpace(err.Error()))
	}
}
