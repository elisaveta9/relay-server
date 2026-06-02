package grpcserver

import (
	"context"
	"errors"
	"log"
	"strings"
	"time"

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

	// TODO: добавить верификацию ACME, прежде чем разрешать устройствам запрашивать домены
	// Разделить этот процесс на два случая: поддомены, выдаваемые relay (для которых не требуется
	// верификация DNS-01), и домены, принадлежащие клиентам (которые должны пройти верификацию DNS-01)
	// Запрашиваемые субдомены релея следует добавлять по отдельности, а не путем публикации
	// wildcard-записи DNS для всей зоны android-tunnel.online
	log.Printf("RegisterDevice domain request rejected: fingerprint=%s domains=%v", fingerprint, req.GetDomains())

	return &controlpb.RegisterResponse{
		Success: false,
		Message: "domain registration is disabled; add domains manually in the admin panel",
	}, nil
}

func (s *ControlServiceImpl) ListDomains(
	ctx context.Context,
	_ *controlpb.ListDomainsRequest,
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
			notifyCtx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
			defer cancel()

			if err := dev.SendFrame(notifyCtx, &tunnelpb.Frame{
				Type:    tunnelpb.FrameType_FRAME_BIND_REJECTED,
				Payload: []byte(domain),
			}); err != nil {
				log.Printf("send BIND_REJECTED after unregister failed: domain=%s fingerprint=%s session=%s err=%v", domain, dev.Fingerprint, dev.SessionID, err)
			}
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
