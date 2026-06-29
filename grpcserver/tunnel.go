package grpcserver

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"strings"
	"time"

	"relay/auditlog"
	"relay/device"
	"relay/registry"
	"relay/storage"

	tunnelpb "relay/proto/tunnel/v2"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

type TunnelServiceImpl struct {
	tunnelpb.UnimplementedTunnelServiceServer
	Store *storage.Repository
}

const (
	terminalFrameSendTimeout     = time.Second
	tunnelSessionCleanupTimeout  = 5 * time.Second
	tunnelResultFrameSendTimeout = 200 * time.Millisecond
)

func (s *TunnelServiceImpl) Tunnel(stream tunnelpb.TunnelService_TunnelServer) (retErr error) {
	fingerprint, err := storage.ClientCertFingerprint(stream.Context())
	if err != nil {
		return status.Errorf(codes.Unauthenticated, "client certificate is required: %v", err)
	}

	hello, err := receiveHello(stream)
	if err != nil {
		return err
	}
	if hello.GetProtocolVersion() != supportedTunnelProtocolVersion {
		_ = sendTunnelError(
			stream,
			tunnelpb.TunnelErrorCode_TUNNEL_ERROR_CODE_PROTOCOL_VERSION_UNSUPPORTED,
			"unsupported tunnel protocol version",
			"",
		)
		return status.Errorf(codes.FailedPrecondition, "unsupported tunnel protocol version: %d", hello.GetProtocolVersion())
	}

	limits := effectiveTunnelLimits(hello)

	session, err := s.Store.OpenDeviceSession(stream.Context(), fingerprint)
	if err != nil {
		return storageError("open device session", err)
	}

	domains, err := s.Store.ListDomainsForFingerprint(stream.Context(), fingerprint)
	if err != nil {
		cleanupCtx, cancel := tunnelSetupCleanupContext(stream.Context())
		if closeErr := s.Store.CloseDeviceSession(cleanupCtx, session.ID); closeErr != nil {
			log.Println("close device session after welcome preparation failed:", closeErr)
		}
		cancel()
		return storageError("list domains for tunnel welcome", err)
	}
	challenges, err := s.Store.ListDomainOwnershipChallengesForFingerprint(stream.Context(), fingerprint)
	if err != nil {
		cleanupCtx, cancel := tunnelSetupCleanupContext(stream.Context())
		if closeErr := s.Store.CloseDeviceSession(cleanupCtx, session.ID); closeErr != nil {
			log.Println("close device session after verification snapshot failed:", closeErr)
		}
		cancel()
		return storageError("list domain verifications for tunnel welcome", err)
	}

	welcomeFrame := tunnelpb.NewWelcomeFrame(&tunnelpb.Welcome{
		SessionId:               session.ID.String(),
		ServerTimeUnixMs:        time.Now().UnixMilli(),
		AcceptedProtocolVersion: supportedTunnelProtocolVersion,
		ServerFeatures:          []string{"tunnel.v2", domainVerificationEventsFeature},
		MaxConcurrentStreams:    limits.maxStreams,
		MaxFrameSizeBytes:       limits.maxFrameSizeBytes,
		PingIntervalSeconds:     limits.pingIntervalSeconds,
		AuthorizedDomains:       tunnelDomainBindings(domains, nil),
		DomainVerifications:     tunnelDomainVerificationUpdates(challenges),
	})
	if err := validateTunnelFrameSize(welcomeFrame, limits.maxFrameSizeBytes); err != nil {
		_ = sendTunnelError(
			stream,
			tunnelpb.TunnelErrorCode_TUNNEL_ERROR_CODE_FRAME_TOO_LARGE,
			"negotiated frame size is too small for tunnel welcome",
			"",
		)
		cleanupCtx, cancel := tunnelSetupCleanupContext(stream.Context())
		if closeErr := s.Store.CloseDeviceSession(cleanupCtx, session.ID); closeErr != nil {
			log.Println("close device session after oversized welcome failed:", closeErr)
		}
		cancel()
		return status.Error(codes.ResourceExhausted, err.Error())
	}
	if err := stream.Send(welcomeFrame); err != nil {
		cleanupCtx, cancel := tunnelSetupCleanupContext(stream.Context())
		if closeErr := s.Store.CloseDeviceSession(cleanupCtx, session.ID); closeErr != nil {
			log.Println("close device session after welcome send failed:", closeErr)
		}
		cancel()
		return err
	}

	dev := device.NewDeviceWithLimits(stream, fingerprint, session.ID.String(), int(limits.maxStreams), limits.maxFrameSizeBytes)
	dev.SetSupportedFeatures(hello.GetSupportedFeatures())
	registry.Global.RegisterDevice(dev)
	log.Printf(
		"tunnel stream opened: fingerprint=%s session=%s client_version=%q protocol_version=%d max_streams=%d max_frame_size_bytes=%d ping_interval_seconds=%d supports_domain_verification_events=%t",
		fingerprint,
		dev.SessionID,
		hello.GetClientVersion(),
		hello.GetProtocolVersion(),
		limits.maxStreams,
		limits.maxFrameSizeBytes,
		limits.pingIntervalSeconds,
		dev.SupportsFeature(domainVerificationEventsFeature),
	)
	log.Printf("Device connected: fingerprint=%s session=%s\n", fingerprint, dev.SessionID)

	defer func() {
		if dev.FirstCloseReason() == "" {
			dev.MarkFirstCloseReason(handlerExitCloseReason(stream.Context(), retErr))
		}
		logTunnelStreamExit(dev, stream.Context(), retErr)
		log.Printf("Device disconnected: fingerprint=%s session=%s\n", fingerprint, dev.SessionID)
		dev.CloseWithReason("handler_exit_cleanup")
		registry.Global.UnregisterDevice(dev)

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		for _, domain := range registry.Global.UnbindDevice(dev) {
			log.Printf("Domain unbound from device: domain=%s fingerprint=%s session=%s\n", domain, dev.Fingerprint, dev.SessionID)
			auditlog.Printf(
				"UNBIND session_cleanup domain=%s fingerprint=%s session=%s",
				domain,
				dev.Fingerprint,
				dev.SessionID,
			)

			if err := s.Store.AddDomainHistoryForFingerprint(
				ctx,
				dev.Fingerprint,
				domain,
				storage.DomainActionUnbind,
			); err != nil {
				log.Println("failed to write domain history (UNBIND):", err)
			}
		}

		if err := s.Store.CloseDeviceSession(ctx, session.ID); err != nil {
			log.Println("close device session failed:", err)
		}
	}()

	for {
		frame, err := stream.Recv()
		if err != nil {
			dev.MarkFirstCloseReason(recvLoopCloseReason(stream.Context(), err))
			return err
		}
		if frame == nil {
			return rejectDeviceProtocolViolation(
				dev,
				tunnelpb.TunnelErrorCode_TUNNEL_ERROR_CODE_INVALID_FRAME,
				"invalid tunnel frame",
				"frame is nil",
			)
		}
		if dev.IsClosed() {
			return status.Error(codes.Canceled, "device tunnel was closed by server")
		}
		if err := validateTunnelFrameSize(frame, dev.MaxFrameSizeBytes()); err != nil {
			return rejectDeviceProtocolViolation(
				dev,
				tunnelpb.TunnelErrorCode_TUNNEL_ERROR_CODE_FRAME_TOO_LARGE,
				"tunnel frame exceeds negotiated size limit",
				err.Error(),
			)
		}

		switch body := frame.GetBody().(type) {

		case *tunnelpb.Frame_BindRequest:
			requestedDomain := strings.ToLower(strings.TrimSpace(body.BindRequest.GetDomain()))
			log.Printf("BIND request: domain=%s fingerprint=%s session=%s\n", requestedDomain, dev.Fingerprint, dev.SessionID)

			if body.BindRequest.GetServeMode() != tunnelpb.ServeMode_SERVE_MODE_HTTPS_PASSTHROUGH {
				log.Println("Bind rejected, unsupported serve mode:", body.BindRequest.GetServeMode())
				sendBindResult(stream.Context(), dev, requestedDomain, false, tunnelpb.TunnelErrorCode_TUNNEL_ERROR_CODE_INVALID_FRAME, "unsupported serve mode")
				continue
			}

			domain, err := storage.NormalizeDomain(requestedDomain)
			if err != nil {
				log.Println("Bind rejected, invalid domain:", requestedDomain)
				sendBindResult(stream.Context(), dev, requestedDomain, false, tunnelpb.TunnelErrorCode_TUNNEL_ERROR_CODE_INVALID_DOMAIN, "invalid domain")
				continue
			}

			domainObj, err := s.Store.AuthorizeBind(stream.Context(), fingerprint, domain)
			if err != nil {
				log.Println("Bind rejected:", err)
				sendBindResult(stream.Context(), dev, domain, false, bindErrorCode(err), bindErrorMessage(err))
				continue
			}

			previous, existed := registry.Global.Bind(domain, dev)
			if existed && previous != nil && previous != dev {
				log.Printf(
					"Domain active binding replaced: domain=%s previous_fingerprint=%s previous_session=%s new_fingerprint=%s new_session=%s\n",
					domain,
					previous.Fingerprint,
					previous.SessionID,
					dev.Fingerprint,
					dev.SessionID,
				)
				sendDomainSync(stream.Context(), s.Store, previous)
			}
			log.Printf("Domain bound to device: domain=%s fingerprint=%s session=%s\n", domain, dev.Fingerprint, dev.SessionID)
			auditlog.Printf(
				"BIND domain=%s fingerprint=%s session=%s replaced=%t",
				domain,
				dev.Fingerprint,
				dev.SessionID,
				existed && previous != nil && previous != dev,
			)

			if domainObj != nil {
				if err := s.Store.AddDomainHistory(
					stream.Context(),
					&domainObj.ID,
					&domainObj.DeviceID,
					domainObj.FQDN,
					storage.DomainActionBind,
				); err != nil {
					log.Println("failed to write domain history (BIND):", err)
				}
			} else {
				if err := s.Store.AddDomainHistory(
					stream.Context(),
					nil,
					nil,
					domain,
					storage.DomainActionBind,
				); err != nil {
					log.Println("failed to write domain history (BIND):", err)
				}
			}
			sendBindResult(stream.Context(), dev, domain, true, tunnelpb.TunnelErrorCode_TUNNEL_ERROR_CODE_UNSPECIFIED, "")
			sendDomainSync(stream.Context(), s.Store, dev)

		case *tunnelpb.Frame_StreamData:
			if c, ok := dev.GetClient(frame.GetStreamId()); ok {
				if _, err := c.Write(body.StreamData); err != nil {
					dev.RemoveStream(frame.GetStreamId())
				}
			}

		case *tunnelpb.Frame_StreamClose:
			dev.RemoveStream(frame.GetStreamId())

		case *tunnelpb.Frame_StreamReset:
			handleStreamReset(dev, frame.GetStreamId(), body.StreamReset)

		case *tunnelpb.Frame_StreamOpenResult:
			if !body.StreamOpenResult.GetSuccess() {
				log.Printf(
					"stream open failed on device: fingerprint=%s session=%s stream_id=%d code=%s message=%q",
					dev.Fingerprint,
					dev.SessionID,
					frame.GetStreamId(),
					body.StreamOpenResult.GetErrorCode(),
					body.StreamOpenResult.GetMessage(),
				)
			}
			if !dev.ResolvePendingOpen(frame.GetStreamId(), body.StreamOpenResult) {
				log.Printf(
					"unexpected stream open result: fingerprint=%s session=%s stream_id=%d success=%t",
					dev.Fingerprint,
					dev.SessionID,
					frame.GetStreamId(),
					body.StreamOpenResult.GetSuccess(),
				)
				if !body.StreamOpenResult.GetSuccess() {
					dev.RemoveStream(frame.GetStreamId())
				}
			}

		case *tunnelpb.Frame_Ping:
			if err := dev.SendFrame(stream.Context(), tunnelpb.NewPongFrameForPing(body.Ping)); err != nil {
				log.Printf("tunnel pong send failed: fingerprint=%s session=%s err=%v", dev.Fingerprint, dev.SessionID, err)
			}

		case *tunnelpb.Frame_UnbindRequest:
			requestedDomain := strings.ToLower(strings.TrimSpace(body.UnbindRequest.GetDomain()))
			log.Printf("UNBIND request: domain=%s fingerprint=%s session=%s\n", requestedDomain, dev.Fingerprint, dev.SessionID)

			domain, err := storage.NormalizeDomain(requestedDomain)
			if err != nil {
				log.Println("Unbind rejected, invalid domain:", requestedDomain)
				sendUnbindResult(stream.Context(), dev, requestedDomain, false, tunnelpb.TunnelErrorCode_TUNNEL_ERROR_CODE_INVALID_DOMAIN, "invalid domain")
				continue
			}

			if cur, ok := registry.Global.Get(domain); !ok {

				log.Println("Unbind rejected, domain not bound:", domain)
				sendUnbindResult(stream.Context(), dev, domain, false, tunnelpb.TunnelErrorCode_TUNNEL_ERROR_CODE_DOMAIN_NOT_REGISTERED, "domain is not bound")
				continue
			} else if cur != dev {
				log.Println("Unbind rejected, device does not own active binding:", domain)
				sendUnbindResult(stream.Context(), dev, domain, false, tunnelpb.TunnelErrorCode_TUNNEL_ERROR_CODE_DOMAIN_NOT_OWNED, "device does not own active binding")
				continue
			}

			registry.Global.Unbind(domain)
			log.Printf("Domain unbound by device: domain=%s fingerprint=%s session=%s\n", domain, dev.Fingerprint, dev.SessionID)
			auditlog.Printf(
				"UNBIND device domain=%s fingerprint=%s session=%s",
				domain,
				dev.Fingerprint,
				dev.SessionID,
			)

			if err := s.Store.AddDomainHistoryForFingerprint(
				stream.Context(),
				dev.Fingerprint,
				domain,
				storage.DomainActionUnbind,
			); err != nil {
				log.Println("failed to write domain history (UNBIND):", err)
				sendUnbindResult(stream.Context(), dev, domain, false, tunnelpb.TunnelErrorCode_TUNNEL_ERROR_CODE_INTERNAL, "failed to write domain history")
				continue
			}

			sendUnbindResult(stream.Context(), dev, domain, true, tunnelpb.TunnelErrorCode_TUNNEL_ERROR_CODE_UNSPECIFIED, "")
			sendDomainSync(stream.Context(), s.Store, dev)

		case *tunnelpb.Frame_Hello:
			return rejectDeviceProtocolViolation(
				dev,
				tunnelpb.TunnelErrorCode_TUNNEL_ERROR_CODE_INVALID_FRAME,
				"unexpected Hello frame",
				"Hello is only valid as the first tunnel frame",
			)

		case *tunnelpb.Frame_Welcome,
			*tunnelpb.Frame_Goaway,
			*tunnelpb.Frame_Error,
			*tunnelpb.Frame_BindResult,
			*tunnelpb.Frame_UnbindResult,
			*tunnelpb.Frame_DomainSync,
			*tunnelpb.Frame_DomainRevoked,
			*tunnelpb.Frame_DomainVerificationUpdate,
			*tunnelpb.Frame_Pong:
			return rejectDeviceProtocolViolation(
				dev,
				tunnelpb.TunnelErrorCode_TUNNEL_ERROR_CODE_INVALID_FRAME,
				"unexpected server frame from client",
				"",
			)

		default:
			return rejectDeviceProtocolViolation(
				dev,
				tunnelpb.TunnelErrorCode_TUNNEL_ERROR_CODE_INVALID_FRAME,
				"invalid tunnel frame",
				"frame body is missing or unsupported",
			)
		}
	}
}

func handleStreamReset(dev *device.Device, streamID uint64, reset *tunnelpb.StreamReset) {
	code := tunnelpb.TunnelErrorCode_TUNNEL_ERROR_CODE_UNSPECIFIED
	message := ""
	if reset != nil {
		code = reset.GetCode()
		message = reset.GetMessage()
	}

	if _, ok := dev.GetClient(streamID); !ok {
		log.Printf(
			"STREAM_RESET ignored for missing stream: fingerprint=%s session=%s stream=%d code=%s message=%q",
			dev.Fingerprint,
			dev.SessionID,
			streamID,
			code,
			message,
		)
		return
	}

	log.Printf(
		"STREAM_RESET from device: fingerprint=%s session=%s stream=%d code=%s message=%q",
		dev.Fingerprint,
		dev.SessionID,
		streamID,
		code,
		message,
	)
	dev.RemoveStream(streamID)
}

func logTunnelStreamExit(dev *device.Device, ctx context.Context, err error) {
	log.Printf(
		"tunnel stream closed: fingerprint=%s session=%s first_close_reason=%q close_reason=%q err=%v",
		dev.Fingerprint,
		dev.SessionID,
		dev.FirstCloseReason(),
		dev.CloseReason(),
		err,
	)
}

func recvLoopCloseReason(ctx context.Context, err error) string {
	switch {
	case err == nil:
		return ""
	case errors.Is(err, io.EOF):
		return "recv_loop_eof"
	case isTunnelTransportClosingError(err):
		return "recv_loop_transport_closing"
	case status.Code(err) == codes.Unavailable:
		return "recv_loop_unavailable"
	case errors.Is(ctx.Err(), context.Canceled), errors.Is(err, context.Canceled), status.Code(err) == codes.Canceled:
		return "recv_loop_context_canceled"
	case isTunnelConnectionResetError(err):
		return "recv_loop_connection_reset"
	default:
		return "recv_loop_error"
	}
}

func handlerExitCloseReason(ctx context.Context, err error) string {
	switch {
	case err == nil:
		return "handler_returned_nil"
	case errors.Is(ctx.Err(), context.Canceled), errors.Is(err, context.Canceled), status.Code(err) == codes.Canceled:
		return "grpc_context_done"
	default:
		return "handler_exit_error"
	}
}

func isTunnelTransportClosingError(err error) bool {
	return err != nil && isTunnelTransportClosingMessage(err.Error())
}

func isTunnelTransportClosingMessage(message string) bool {
	return strings.Contains(strings.ToLower(message), "transport is closing")
}

func isTunnelConnectionResetError(err error) bool {
	return err != nil && isTunnelConnectionResetMessage(err.Error())
}

func isTunnelConnectionResetMessage(message string) bool {
	msg := strings.ToLower(message)
	return strings.Contains(msg, "connection reset") || strings.Contains(msg, "forcibly closed")
}

func sendBindResult(ctx context.Context, dev *device.Device, domain string, success bool, code tunnelpb.TunnelErrorCode, message string) error {
	ctx, cancel := context.WithTimeout(ctx, tunnelResultFrameSendTimeout)
	defer cancel()

	err := dev.SendFrame(ctx, tunnelpb.NewBindResultFrame(domain, success, code, message))
	if err != nil {
		log.Printf("send bind result failed: domain=%s fingerprint=%s session=%s err=%v", domain, dev.Fingerprint, dev.SessionID, err)
	}
	return err
}

func sendUnbindResult(ctx context.Context, dev *device.Device, domain string, success bool, code tunnelpb.TunnelErrorCode, message string) error {
	ctx, cancel := context.WithTimeout(ctx, tunnelResultFrameSendTimeout)
	defer cancel()

	err := dev.SendFrame(ctx, tunnelpb.NewUnbindResultFrame(domain, success, code, message))
	if err != nil {
		log.Printf("send unbind result failed: domain=%s fingerprint=%s session=%s err=%v", domain, dev.Fingerprint, dev.SessionID, err)
	}
	return err
}

func tunnelSetupCleanupContext(parent context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.WithoutCancel(parent), tunnelSessionCleanupTimeout)
}

func sendDomainSync(ctx context.Context, store *storage.Repository, dev *device.Device) {
	domains, err := store.ListDomainsForFingerprint(ctx, dev.Fingerprint)
	if err != nil {
		log.Printf("load domains for DomainSync failed: fingerprint=%s session=%s err=%v", dev.Fingerprint, dev.SessionID, err)
		return
	}
	if err := dev.SendFrame(ctx, tunnelpb.NewDomainSyncFrame(tunnelDomainBindings(domains, dev))); err != nil {
		log.Printf("send DomainSync failed: fingerprint=%s session=%s err=%v", dev.Fingerprint, dev.SessionID, err)
	}
}

func bindErrorCode(err error) tunnelpb.TunnelErrorCode {
	switch {
	case errors.Is(err, storage.ErrDomainInvalid):
		return tunnelpb.TunnelErrorCode_TUNNEL_ERROR_CODE_INVALID_DOMAIN
	case errors.Is(err, storage.ErrDomainNotFound):
		return tunnelpb.TunnelErrorCode_TUNNEL_ERROR_CODE_DOMAIN_NOT_REGISTERED
	case errors.Is(err, storage.ErrDomainNotOwned):
		return tunnelpb.TunnelErrorCode_TUNNEL_ERROR_CODE_DOMAIN_NOT_OWNED
	case errors.Is(err, storage.ErrDomainDisabled):
		return tunnelpb.TunnelErrorCode_TUNNEL_ERROR_CODE_DOMAIN_DISABLED
	case errors.Is(err, storage.ErrDeviceRevoked):
		return tunnelpb.TunnelErrorCode_TUNNEL_ERROR_CODE_DEVICE_REVOKED
	default:
		return tunnelpb.TunnelErrorCode_TUNNEL_ERROR_CODE_INTERNAL
	}
}

func bindErrorMessage(err error) string {
	switch {
	case errors.Is(err, storage.ErrDomainInvalid):
		return "invalid domain"
	case errors.Is(err, storage.ErrDomainNotFound):
		return "domain is not registered"
	case errors.Is(err, storage.ErrDomainNotOwned):
		return "domain belongs to another device"
	case errors.Is(err, storage.ErrDomainDisabled):
		return "domain is disabled"
	case errors.Is(err, storage.ErrDeviceRevoked):
		return "device is revoked"
	default:
		return "bind rejected"
	}
}

type tunnelLimits struct {
	maxStreams          uint32
	maxFrameSizeBytes   uint32
	pingIntervalSeconds uint32
}

func receiveHello(stream tunnelpb.TunnelService_TunnelServer) (*tunnelpb.Hello, error) {
	frame, err := stream.Recv()
	if err != nil {
		return nil, err
	}
	if frame == nil {
		_ = sendTunnelError(
			stream,
			tunnelpb.TunnelErrorCode_TUNNEL_ERROR_CODE_INVALID_FRAME,
			"first frame must be Hello",
			"frame is nil",
		)
		return nil, status.Error(codes.FailedPrecondition, "first frame must be Hello: frame is nil")
	}
	body, ok := frame.GetBody().(*tunnelpb.Frame_Hello)
	if !ok || body.Hello == nil {
		_ = sendTunnelError(
			stream,
			tunnelpb.TunnelErrorCode_TUNNEL_ERROR_CODE_INVALID_FRAME,
			"first frame must be Hello",
			"",
		)
		return nil, status.Error(codes.FailedPrecondition, "first frame must be Hello")
	}
	return body.Hello, nil
}

func sendTunnelError(stream tunnelpb.TunnelService_TunnelServer, code tunnelpb.TunnelErrorCode, message string, details string) error {
	return stream.Send(tunnelpb.NewTunnelErrorFrame(code, message, details))
}

func rejectDeviceProtocolViolation(dev *device.Device, code tunnelpb.TunnelErrorCode, message string, details string) error {
	ctx, cancel := context.WithTimeout(context.Background(), terminalFrameSendTimeout)
	defer cancel()
	if err := dev.CloseWithFrameReasonAndWait(
		ctx,
		tunnelpb.NewTunnelErrorFrame(code, message, details),
		"protocol_violation",
	); err != nil {
		log.Printf(
			"send terminal protocol error failed: fingerprint=%s session=%s err=%v",
			dev.Fingerprint,
			dev.SessionID,
			err,
		)
	}
	return protocolViolationStatus(message, details)
}

func protocolViolationStatus(message string, details string) error {
	if details != "" {
		return status.Errorf(codes.FailedPrecondition, "%s: %s", message, details)
	}
	return status.Error(codes.FailedPrecondition, message)
}

func validateTunnelFrameSize(frame *tunnelpb.Frame, limit uint32) error {
	if limit == 0 {
		return nil
	}
	size := proto.Size(frame)
	if size > int(limit) {
		return fmt.Errorf("frame size=%d limit=%d", size, limit)
	}
	return nil
}

func effectiveTunnelLimits(hello *tunnelpb.Hello) tunnelLimits {
	serverPolicyMaxStreams := uint32(envInt("RELAY_MAX_STREAMS_PER_DEVICE", defaultMaxStreamsPerDevice))
	serverCurrentCapacityLimit := uint32(envInt("RELAY_SERVER_CURRENT_CAPACITY_STREAM_LIMIT", int(serverPolicyMaxStreams)))
	domainPolicyLimit := uint32(envInt("RELAY_DOMAIN_POLICY_STREAM_LIMIT", int(serverPolicyMaxStreams)))
	deviceMaxStreams := hello.GetMaxConcurrentStreams()
	if deviceMaxStreams == 0 {
		deviceMaxStreams = serverPolicyMaxStreams
	}

	serverMaxFrameSize := configuredMaxFrameSizeBytes()
	deviceMaxFrameSize := hello.GetMaxFrameSizeBytes()
	if deviceMaxFrameSize == 0 {
		deviceMaxFrameSize = serverMaxFrameSize
	}

	pingInterval := uint32(envInt("RELAY_PING_INTERVAL_SECONDS", defaultPingIntervalSeconds))
	if preferred := hello.GetPreferredPingIntervalSeconds(); preferred > 0 && preferred < pingInterval {
		pingInterval = preferred
	}

	return tunnelLimits{
		maxStreams: minUint32(
			deviceMaxStreams,
			serverPolicyMaxStreams,
			serverCurrentCapacityLimit,
			domainPolicyLimit,
		),
		maxFrameSizeBytes:   minUint32(deviceMaxFrameSize, serverMaxFrameSize),
		pingIntervalSeconds: pingInterval,
	}
}

func tunnelDomainBindings(domains []storage.Domain, target *device.Device) []*tunnelpb.DomainBinding {
	out := make([]*tunnelpb.DomainBinding, 0, len(domains))
	for _, domain := range domains {
		active, exists := registry.Global.Get(domain.FQDN)
		bound := target != nil && exists && active == target
		out = append(out, &tunnelpb.DomainBinding{
			Domain: domain.FQDN,
			Status: tunnelDomainStatus(domain.Status),
			Bound:  bound,
		})
	}
	return out
}

func tunnelDomainStatus(status storage.DomainStatus) tunnelpb.DomainStatus {
	switch status {
	case storage.DomainStatusRegistered, storage.DomainStatusBound:
		return tunnelpb.DomainStatus_DOMAIN_STATUS_REGISTERED
	case storage.DomainStatusDisabled:
		return tunnelpb.DomainStatus_DOMAIN_STATUS_DISABLED
	default:
		return tunnelpb.DomainStatus_DOMAIN_STATUS_UNSPECIFIED
	}
}

func minUint32(values ...uint32) uint32 {
	if len(values) == 0 {
		return 0
	}
	min := values[0]
	for _, value := range values[1:] {
		if value < min {
			min = value
		}
	}
	return min
}
