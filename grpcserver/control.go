package grpcserver

import (
	"context"
	"errors"
	"log"
	"os"
	"strconv"
	"strings"
	"time"

	controlpb "relay/proto/control/v2"
	tunnelpb "relay/proto/tunnel/v2"
	"relay/registry"
	"relay/storage"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type ControlServiceImpl struct {
	controlpb.UnimplementedControlServiceServer
	Store *storage.Repository
}

const (
	supportedTunnelProtocolVersion = 2
	defaultMaxStreamsPerDevice     = 128
	defaultMaxFrameSizeBytes       = 8 * 1024 * 1024
	defaultPingIntervalSeconds     = 30
)

func (s *ControlServiceImpl) UpdateDeviceRegistration(
	ctx context.Context,
	req *controlpb.UpdateDeviceRegistrationRequest,
) (*controlpb.UpdateDeviceRegistrationResponse, error) {
	fingerprint, err := storage.ClientCertFingerprint(ctx)
	if err != nil {
		return nil, status.Errorf(codes.Unauthenticated, "client certificate is required: %v", err)
	}

	if _, err := s.Store.TouchDeviceRegistration(ctx, fingerprint); err != nil {
		return nil, storageError("update device registration", err)
	}

	domains, err := s.Store.ListDomainsForFingerprint(ctx, fingerprint)
	if err != nil {
		return nil, storageError("update device registration", err)
	}

	log.Printf("Device registration updated from mTLS identity: fingerprint=%s client_version=%s protocol_version=%d", fingerprint, req.GetClientVersion(), req.GetProtocolVersion())

	return &controlpb.UpdateDeviceRegistrationResponse{
		Success:                 true,
		Message:                 "ok",
		AcceptedProtocolVersion: supportedTunnelProtocolVersion,
		ServerFeatures:          []string{"control.v2", "tunnel.v2"},
		Domains:                 domainInfos(domains),
	}, nil
}

func (s *ControlServiceImpl) GetDeviceConfig(
	ctx context.Context,
	_ *controlpb.GetDeviceConfigRequest,
) (*controlpb.GetDeviceConfigResponse, error) {
	fingerprint, err := storage.ClientCertFingerprint(ctx)
	if err != nil {
		return nil, status.Errorf(codes.Unauthenticated, "client certificate is required: %v", err)
	}

	domains, err := s.Store.ListDomainsForFingerprint(ctx, fingerprint)
	if err != nil {
		return nil, storageError("get device config", err)
	}

	return deviceConfig(domainInfos(domains)), nil
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

	return &controlpb.ListDomainsResponse{Domains: domainInfos(domains)}, nil
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

			if err := dev.SendFrame(notifyCtx, tunnelpb.NewDomainRevokedFrameWithReason(domain, "domain unregistered", tunnelpb.DomainRevokeReason_DOMAIN_REVOKE_REASON_DOMAIN_UNREGISTERED)); err != nil {
				log.Printf("send domain revoked after unregister failed: domain=%s fingerprint=%s session=%s err=%v", domain, dev.Fingerprint, dev.SessionID, err)
			}
			sendDomainSync(notifyCtx, s.Store, dev)
		}
	}

	if !deleted {
		return &controlpb.UnregisterDomainResponse{
			Success:   false,
			Message:   "domain not found",
			ErrorCode: controlpb.ControlErrorCode_CONTROL_ERROR_CODE_DOMAIN_NOT_FOUND,
		}, nil
	}

	return &controlpb.UnregisterDomainResponse{Success: true, Message: "ok"}, nil
}

func (s *ControlServiceImpl) RegisterDomain(
	ctx context.Context,
	_ *controlpb.RegisterDomainRequest,
) (*controlpb.DomainRegistrationResponse, error) {
	if _, err := storage.ClientCertFingerprint(ctx); err != nil {
		return nil, status.Errorf(codes.Unauthenticated, "client certificate is required: %v", err)
	}
	return domainRegistrationDisabled(), nil
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

func domainRegistrationDisabled() *controlpb.DomainRegistrationResponse {
	return &controlpb.DomainRegistrationResponse{
		Success:   false,
		Message:   "domain registration is disabled; add domains manually in the admin panel",
		ErrorCode: controlpb.ControlErrorCode_CONTROL_ERROR_CODE_DNS_PROOF_REQUIRED,
	}
}

func deviceConfig(domains []*controlpb.DomainInfo) *controlpb.GetDeviceConfigResponse {
	return &controlpb.GetDeviceConfigResponse{
		MinSupportedTunnelProtocolVersion: supportedTunnelProtocolVersion,
		MaxSupportedTunnelProtocolVersion: supportedTunnelProtocolVersion,
		PreferredTunnelProtocolVersion:    supportedTunnelProtocolVersion,
		RelayGrpcEndpoint:                 os.Getenv("RELAY_GRPC_ENDPOINT"),
		PolicyMaxConcurrentStreams:        uint32(envInt("RELAY_MAX_STREAMS_PER_DEVICE", defaultMaxStreamsPerDevice)),
		PolicyMaxFrameSizeBytes:           configuredMaxFrameSizeBytes(),
		DefaultPingIntervalSeconds:        uint32(envInt("RELAY_PING_INTERVAL_SECONDS", defaultPingIntervalSeconds)),
		ServerFeatures:                    []string{"control.v2", "tunnel.v2"},
		Domains:                           domains,
	}
}

func configuredMaxFrameSizeBytes() uint32 {
	return minUint32(
		uint32(envInt("RELAY_MAX_FRAME_SIZE_BYTES", defaultMaxFrameSizeBytes)),
		uint32(grpcMaxMessageSizeBytes),
	)
}

func domainInfos(domains []storage.Domain) []*controlpb.DomainInfo {
	out := make([]*controlpb.DomainInfo, 0, len(domains))
	for _, domain := range domains {
		_, active := registry.Global.Get(domain.FQDN)
		out = append(out, &controlpb.DomainInfo{
			Domain:          domain.FQDN,
			Status:          controlDomainStatus(domain.Status),
			ActiveBinding:   active,
			CreatedAtUnixMs: domain.CreatedAt.UnixNano() / int64(time.Millisecond),
			UpdatedAtUnixMs: domain.UpdatedAt.UnixNano() / int64(time.Millisecond),
		})
	}
	return out
}

func controlDomainStatus(status storage.DomainStatus) controlpb.DomainStatus {
	switch status {
	case storage.DomainStatusRegistered, storage.DomainStatusBound:
		return controlpb.DomainStatus_DOMAIN_STATUS_REGISTERED
	case storage.DomainStatusDisabled:
		return controlpb.DomainStatus_DOMAIN_STATUS_DISABLED
	default:
		return controlpb.DomainStatus_DOMAIN_STATUS_UNSPECIFIED
	}
}

func envInt(key string, def int) int {
	if value := strings.TrimSpace(os.Getenv(key)); value != "" {
		if parsed, err := strconv.Atoi(value); err == nil && parsed > 0 {
			return parsed
		}
	}
	return def
}
