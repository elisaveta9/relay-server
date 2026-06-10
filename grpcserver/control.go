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
	Store       *storage.Repository
	TXTResolver txtResolver
}

const (
	supportedTunnelProtocolVersion = 2
	defaultMaxStreamsPerDevice     = 128
	defaultMaxFrameSizeBytes       = 8 * 1024 * 1024
	defaultPingIntervalSeconds     = 30
	defaultDNSChallengeTTLSeconds  = 24 * 60 * 60
	defaultDNSInstructionTTL       = 300
	defaultMaxActiveDNSChallenges  = 32
	defaultDNSVerifyMinInterval    = 60 * time.Second
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
	challenges, err := s.Store.ListDomainOwnershipChallengesForFingerprint(ctx, fingerprint)
	if err != nil {
		return nil, storageError("update device registration", err)
	}

	log.Printf("Device registration updated from mTLS identity: fingerprint=%s client_version=%s protocol_version=%d", fingerprint, req.GetClientVersion(), req.GetProtocolVersion())

	return &controlpb.UpdateDeviceRegistrationResponse{
		Success:                 true,
		Message:                 "ok",
		AcceptedProtocolVersion: supportedTunnelProtocolVersion,
		ServerFeatures:          []string{"control.v2", "tunnel.v2", "domain-verification-events"},
		Domains:                 domainInfos(domains),
		DomainVerifications:     controlDomainVerificationInfos(challenges),
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
	challenges, err := s.Store.ListDomainOwnershipChallengesForFingerprint(ctx, fingerprint)
	if err != nil {
		return nil, storageError("get device config", err)
	}

	return deviceConfig(
		domainInfos(domains),
		controlDomainVerificationInfos(challenges),
	), nil
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
	challenges, err := s.Store.ListDomainOwnershipChallengesForFingerprint(ctx, fingerprint)
	if err != nil {
		return nil, storageError("list domain verifications", err)
	}

	return &controlpb.ListDomainsResponse{
		Domains:             domainInfos(domains),
		DomainVerifications: controlDomainVerificationInfos(challenges),
	}, nil
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
	req *controlpb.RegisterDomainRequest,
) (*controlpb.DomainRegistrationResponse, error) {
	fingerprint, err := storage.ClientCertFingerprint(ctx)
	if err != nil {
		return nil, status.Errorf(codes.Unauthenticated, "client certificate is required: %v", err)
	}
	domain, err := storage.NormalizeDomain(req.GetDomain())
	if err != nil {
		return domainRegistrationFailure("invalid domain", controlpb.ControlErrorCode_CONTROL_ERROR_CODE_INVALID_DOMAIN), nil
	}

	proof := req.GetProof()
	if proof == nil {
		challenge, err := s.Store.GetOrCreateDomainOwnershipChallenge(
			ctx,
			fingerprint,
			domain,
			configuredDNSChallengeTTL(),
			configuredDNSInitialVerificationDelay(),
			envInt("RELAY_MAX_ACTIVE_DNS_CHALLENGES_PER_DEVICE", defaultMaxActiveDNSChallenges),
		)
		if errors.Is(err, storage.ErrDomainAlreadyRegistered) {
			existing, loadErr := s.Store.GetOwnedDomain(ctx, fingerprint, domain)
			if loadErr != nil {
				return nil, storageError("load registered domain", loadErr)
			}
			return domainRegistrationSuccess(existing), nil
		}
		if errors.Is(err, storage.ErrDomainAlreadyUsed) {
			return domainRegistrationFailure("domain already belongs to another device", controlpb.ControlErrorCode_CONTROL_ERROR_CODE_DOMAIN_ALREADY_USED), nil
		}
		if errors.Is(err, storage.ErrDomainOwnershipChallengeLimit) {
			return domainRegistrationFailure("too many active DNS proof challenges", controlpb.ControlErrorCode_CONTROL_ERROR_CODE_RATE_LIMITED), nil
		}
		if err != nil {
			return nil, storageError("create DNS proof challenge", err)
		}
		return domainRegistrationChallenge(challenge, configuredDNSInstructionTTL()), nil
	}

	if proof.GetType() != controlpb.ProofType_PROOF_TYPE_DNS_TXT {
		return domainRegistrationFailure("DNS TXT proof is required", controlpb.ControlErrorCode_CONTROL_ERROR_CODE_DNS_PROOF_REQUIRED), nil
	}
	challenge, err := s.Store.GetDomainOwnershipChallenge(ctx, fingerprint, domain)
	if errors.Is(err, storage.ErrDomainOwnershipChallengeNotFound) || errors.Is(err, storage.ErrDomainOwnershipChallengeExpired) {
		return domainRegistrationFailure("DNS proof challenge is missing or expired; request a new challenge", controlpb.ControlErrorCode_CONTROL_ERROR_CODE_DNS_PROOF_REQUIRED), nil
	}
	if err != nil {
		return nil, storageError("load DNS proof challenge", err)
	}
	if normalizeDNSName(proof.GetRecordName()) != normalizeDNSName(challenge.RecordName) ||
		proof.GetRecordValue() != challenge.RecordValue {
		return domainRegistrationFailure("DNS proof does not match the active challenge", controlpb.ControlErrorCode_CONTROL_ERROR_CODE_DNS_PROOF_INVALID), nil
	}

	verifyMinInterval := configuredDNSVerifyMinInterval()
	challenge, err = s.Store.BeginDomainOwnershipVerification(
		ctx,
		fingerprint,
		domain,
		challenge.RecordValue,
		configuredMaxDNSVerifyAttempts(challenge, verifyMinInterval),
		verifyMinInterval,
	)
	if errors.Is(err, storage.ErrDomainOwnershipVerificationLimit) ||
		errors.Is(err, storage.ErrDomainOwnershipVerificationWait) {
		return domainRegistrationFailure("DNS proof verification rate limit exceeded", controlpb.ControlErrorCode_CONTROL_ERROR_CODE_RATE_LIMITED), nil
	}
	if errors.Is(err, storage.ErrDomainOwnershipChallengeNotFound) ||
		errors.Is(err, storage.ErrDomainOwnershipChallengeExpired) ||
		errors.Is(err, storage.ErrDomainOwnershipProofInvalid) {
		return domainRegistrationFailure("DNS proof challenge is no longer valid", controlpb.ControlErrorCode_CONTROL_ERROR_CODE_DNS_PROOF_INVALID), nil
	}
	if err != nil {
		return nil, storageError("begin DNS proof verification", err)
	}

	records, err := s.txtResolver().LookupTXT(ctx, absoluteDNSName(challenge.RecordName))
	if err != nil || !containsTXTRecord(records, challenge.RecordValue) {
		message := "required DNS TXT record was not found"
		if err != nil {
			message = "DNS TXT lookup failed: " + err.Error()
		}
		next := nextDNSVerificationAt(challenge, time.Now().UTC())
		updated, recordErr := s.Store.RecordDomainOwnershipVerificationFailure(
			ctx,
			challenge.ID,
			challenge.RecordValue,
			message,
			next,
		)
		if recordErr != nil {
			return nil, storageError("record DNS proof verification failure", recordErr)
		}
		if updated {
			challenge.LastError = message
			challenge.NextVerificationAt = &next
			challenge.Device.CertFingerprint = fingerprint
			notifyDomainVerificationUpdate(s.Store, challenge, false)
		}
		return domainRegistrationVerificationFailure(
			message,
			controlpb.ControlErrorCode_CONTROL_ERROR_CODE_DNS_PROOF_INVALID,
			challenge,
		), nil
	}

	registered, err := s.Store.CompleteDomainOwnershipChallenge(ctx, fingerprint, domain, challenge.RecordValue)
	if errors.Is(err, storage.ErrDomainAlreadyUsed) {
		return domainRegistrationFailure("domain already belongs to another device", controlpb.ControlErrorCode_CONTROL_ERROR_CODE_DOMAIN_ALREADY_USED), nil
	}
	if errors.Is(err, storage.ErrDomainOwnershipChallengeNotFound) ||
		errors.Is(err, storage.ErrDomainOwnershipChallengeExpired) ||
		errors.Is(err, storage.ErrDomainOwnershipProofInvalid) {
		return domainRegistrationFailure("DNS proof challenge is no longer valid", controlpb.ControlErrorCode_CONTROL_ERROR_CODE_DNS_PROOF_INVALID), nil
	}
	if err != nil {
		return nil, storageError("register verified domain", err)
	}
	now := time.Now().UTC()
	challenge.Status = storage.DomainOwnershipChallengeStatusVerified
	challenge.NextVerificationAt = nil
	challenge.LastError = ""
	challenge.VerifiedAt = &now
	challenge.Device.CertFingerprint = fingerprint
	notifyDomainVerificationUpdate(s.Store, challenge, true)
	return domainRegistrationSuccess(registered), nil
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

func domainRegistrationFailure(message string, code controlpb.ControlErrorCode) *controlpb.DomainRegistrationResponse {
	return &controlpb.DomainRegistrationResponse{
		Success:   false,
		Message:   message,
		ErrorCode: code,
	}
}

func domainRegistrationVerificationFailure(
	message string,
	code controlpb.ControlErrorCode,
	challenge *storage.DomainOwnershipChallenge,
) *controlpb.DomainRegistrationResponse {
	response := domainRegistrationFailure(message, code)
	response.Verification = controlDomainVerificationInfo(challenge)
	return response
}

func domainRegistrationChallenge(
	challenge *storage.DomainOwnershipChallenge,
	instructionTTL uint32,
) *controlpb.DomainRegistrationResponse {
	return &controlpb.DomainRegistrationResponse{
		Success:   false,
		Message:   "create the DNS TXT record and repeat RegisterDomain with the returned proof",
		ErrorCode: controlpb.ControlErrorCode_CONTROL_ERROR_CODE_DNS_PROOF_REQUIRED,
		DnsInstruction: &controlpb.DNSInstruction{
			RecordName:      challenge.RecordName,
			RecordType:      controlpb.DNSRecordType_DNS_RECORD_TYPE_TXT,
			RecordValue:     challenge.RecordValue,
			TtlSeconds:      instructionTTL,
			Purpose:         "relay domain ownership verification",
			ExpiresAtUnixMs: challenge.ExpiresAt.UnixMilli(),
		},
		Verification: controlDomainVerificationInfo(challenge),
	}
}

func domainRegistrationSuccess(domain *storage.Domain) *controlpb.DomainRegistrationResponse {
	info := domainInfos([]storage.Domain{*domain})[0]
	return &controlpb.DomainRegistrationResponse{
		Success: true,
		Message: "domain registered",
		Domain:  info,
	}
}

func (s *ControlServiceImpl) txtResolver() txtResolver {
	if s.TXTResolver != nil {
		return s.TXTResolver
	}
	return netTXTResolver{}
}

func normalizeDNSName(name string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(name)), ".")
}

func absoluteDNSName(name string) string {
	return normalizeDNSName(name) + "."
}

func containsTXTRecord(records []string, expected string) bool {
	for _, record := range records {
		if strings.TrimSpace(record) == expected {
			return true
		}
	}
	return false
}

func deviceConfig(
	domains []*controlpb.DomainInfo,
	verifications []*controlpb.DomainVerificationInfo,
) *controlpb.GetDeviceConfigResponse {
	return &controlpb.GetDeviceConfigResponse{
		MinSupportedTunnelProtocolVersion: supportedTunnelProtocolVersion,
		MaxSupportedTunnelProtocolVersion: supportedTunnelProtocolVersion,
		PreferredTunnelProtocolVersion:    supportedTunnelProtocolVersion,
		RelayGrpcEndpoint:                 os.Getenv("RELAY_GRPC_ENDPOINT"),
		PolicyMaxConcurrentStreams:        uint32(envInt("RELAY_MAX_STREAMS_PER_DEVICE", defaultMaxStreamsPerDevice)),
		PolicyMaxFrameSizeBytes:           configuredMaxFrameSizeBytes(),
		DefaultPingIntervalSeconds:        uint32(envInt("RELAY_PING_INTERVAL_SECONDS", defaultPingIntervalSeconds)),
		ServerFeatures:                    []string{"control.v2", "tunnel.v2", "domain-verification-events"},
		Domains:                           domains,
		DomainVerifications:               verifications,
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

func configuredDNSChallengeTTL() time.Duration {
	return time.Duration(envInt("RELAY_DNS_CHALLENGE_TTL_SECONDS", defaultDNSChallengeTTLSeconds)) * time.Second
}

func configuredDNSInstructionTTL() uint32 {
	return uint32(envInt("RELAY_DNS_INSTRUCTION_TTL_SECONDS", defaultDNSInstructionTTL))
}

func configuredDNSVerifyMinInterval() time.Duration {
	return time.Duration(envInt(
		"RELAY_DNS_VERIFY_MIN_INTERVAL_SECONDS",
		int(defaultDNSVerifyMinInterval/time.Second),
	)) * time.Second
}

func configuredMaxDNSVerifyAttempts(
	challenge *storage.DomainOwnershipChallenge,
	minInterval time.Duration,
) uint32 {
	if value := strings.TrimSpace(os.Getenv("RELAY_MAX_DNS_VERIFY_ATTEMPTS_PER_CHALLENGE")); value != "" {
		if parsed, err := strconv.ParseUint(value, 10, 32); err == nil && parsed > 0 {
			return uint32(parsed)
		}
	}

	lifetime := challenge.ExpiresAt.Sub(challenge.CreatedAt)
	if lifetime <= 0 {
		lifetime = configuredDNSChallengeTTL()
	}
	if minInterval <= 0 {
		return 1
	}

	attempts := uint64((lifetime + minInterval - 1) / minInterval)
	if attempts < 1 {
		return 1
	}
	if attempts > uint64(^uint32(0)) {
		return ^uint32(0)
	}
	return uint32(attempts)
}
