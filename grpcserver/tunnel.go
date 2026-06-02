package grpcserver

import (
	"context"
	"errors"
	"log"
	"strings"
	"time"

	"relay/device"
	"relay/registry"
	"relay/storage"

	tunnelpb "relay/proto/tunnel"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type TunnelServiceImpl struct {
	tunnelpb.UnimplementedTunnelServiceServer
	Store *storage.Repository
}

func (s *TunnelServiceImpl) Tunnel(stream tunnelpb.TunnelService_TunnelServer) error {
	fingerprint, err := storage.ClientCertFingerprint(stream.Context())
	if err != nil {
		return status.Errorf(codes.Unauthenticated, "client certificate is required: %v", err)
	}

	session, err := s.Store.OpenDeviceSession(stream.Context(), fingerprint)
	if err != nil {
		return storageError("open device session", err)
	}

	dev := device.NewDevice(stream, fingerprint, session.ID.String())
	log.Printf("Device connected: fingerprint=%s session=%s\n", fingerprint, dev.SessionID)

	defer func() {
		log.Printf("Device disconnected: fingerprint=%s session=%s\n", fingerprint, dev.SessionID)
		dev.Close()

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		for _, domain := range registry.Global.UnbindDevice(dev) {
			log.Printf("Domain unbound from device: domain=%s fingerprint=%s session=%s\n", domain, dev.Fingerprint, dev.SessionID)

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
			return err
		}

		switch frame.Type {

		case tunnelpb.FrameType_FRAME_BIND_REQUEST:
			requestedDomain := strings.ToLower(strings.TrimSpace(string(frame.Payload)))
			log.Printf("BIND request: domain=%s fingerprint=%s session=%s\n", requestedDomain, dev.Fingerprint, dev.SessionID)

			domain, err := storage.NormalizeDomain(requestedDomain)
			if err != nil {
				log.Println("Bind rejected, invalid domain:", requestedDomain)
				sendBindRejected(dev, requestedDomain)
				continue
			}

			domainObj, err := s.Store.AuthorizeBind(stream.Context(), fingerprint, domain)
			if err != nil {
				if errors.Is(err, storage.ErrDomainNotOwned) {
					log.Println("Bind rejected, device does not own domain:", domain)
				} else {
					log.Println("Bind rejected:", err)
				}
				sendBindRejected(dev, domain)
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
			}
			log.Printf("Domain bound to device: domain=%s fingerprint=%s session=%s\n", domain, dev.Fingerprint, dev.SessionID)

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
			if err := dev.SendFrame(stream.Context(), &tunnelpb.Frame{
				Type:    tunnelpb.FrameType_FRAME_BIND_OK,
				Payload: []byte(domain),
			}); err != nil {
				log.Printf("send BIND_OK failed: domain=%s fingerprint=%s session=%s err=%v", domain, dev.Fingerprint, dev.SessionID, err)
			}

		case tunnelpb.FrameType_FRAME_DATA:
			if c, ok := dev.GetClient(frame.StreamId); ok {
				if _, err := c.Write(frame.Payload); err != nil {
					dev.RemoveStream(frame.StreamId)
				}
			}

		case tunnelpb.FrameType_FRAME_CLOSE:
			dev.RemoveStream(frame.StreamId)

		case tunnelpb.FrameType_FRAME_PING:
			if err := dev.SendFrame(stream.Context(), &tunnelpb.Frame{
				Type:    tunnelpb.FrameType_FRAME_PONG,
				Payload: frame.Payload,
			}); err != nil {
				log.Printf("send PONG failed: fingerprint=%s session=%s err=%v", dev.Fingerprint, dev.SessionID, err)
			}

		case tunnelpb.FrameType_FRAME_UNBIND_REQUEST:
			requestedDomain := strings.ToLower(strings.TrimSpace(string(frame.Payload)))
			log.Printf("UNBIND request: domain=%s fingerprint=%s session=%s\n", requestedDomain, dev.Fingerprint, dev.SessionID)

			domain, err := storage.NormalizeDomain(requestedDomain)
			if err != nil {
				log.Println("Unbind rejected, invalid domain:", requestedDomain)
				sendUnbindRejected(dev, requestedDomain)
				continue
			}

			if cur, ok := registry.Global.Get(domain); !ok {

				log.Println("Unbind rejected, domain not bound:", domain)
				sendUnbindRejected(dev, domain)
				continue
			} else if cur != dev {
				log.Println("Unbind rejected, device does not own active binding:", domain)
				sendUnbindRejected(dev, domain)
				continue
			}

			registry.Global.Unbind(domain)
			log.Printf("Domain unbound by device: domain=%s fingerprint=%s session=%s\n", domain, dev.Fingerprint, dev.SessionID)

			if err := s.Store.AddDomainHistoryForFingerprint(
				stream.Context(),
				dev.Fingerprint,
				domain,
				storage.DomainActionUnbind,
			); err != nil {
				log.Println("failed to write domain history (UNBIND):", err)
				if err := dev.SendFrame(stream.Context(), &tunnelpb.Frame{
					Type:    tunnelpb.FrameType_FRAME_UNBIND_REJECTED,
					Payload: []byte(domain),
				}); err != nil {
					log.Printf("send UNBIND_REJECTED failed: domain=%s fingerprint=%s session=%s err=%v", domain, dev.Fingerprint, dev.SessionID, err)
				}
				continue
			}

			if err := dev.SendFrame(stream.Context(), &tunnelpb.Frame{
				Type:    tunnelpb.FrameType_FRAME_UNBIND_OK,
				Payload: []byte(domain),
			}); err != nil {
				log.Printf("send UNBIND_OK failed: domain=%s fingerprint=%s session=%s err=%v", domain, dev.Fingerprint, dev.SessionID, err)
			}
		}
	}
}

func sendBindRejected(dev *device.Device, domain string) {
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	if err := dev.SendFrame(ctx, &tunnelpb.Frame{
		Type:    tunnelpb.FrameType_FRAME_BIND_REJECTED,
		Payload: []byte(domain),
	}); err != nil {
		log.Printf("send BIND_REJECTED failed: domain=%s fingerprint=%s session=%s err=%v", domain, dev.Fingerprint, dev.SessionID, err)
	}
}

func sendUnbindRejected(dev *device.Device, domain string) {
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	if err := dev.SendFrame(ctx, &tunnelpb.Frame{
		Type:    tunnelpb.FrameType_FRAME_UNBIND_REJECTED,
		Payload: []byte(domain),
	}); err != nil {
		log.Printf("send UNBIND_REJECTED failed: domain=%s fingerprint=%s session=%s err=%v", domain, dev.Fingerprint, dev.SessionID, err)
	}
}
