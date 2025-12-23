package grpcserver

import (
	"log"
	"strings"

	"relay/device"
	"relay/registry"

	tunnelpb "relay/proto/tunnel"
)

type TunnelServiceImpl struct {
	tunnelpb.UnimplementedTunnelServiceServer
}

func (s *TunnelServiceImpl) Tunnel(stream tunnelpb.TunnelService_TunnelServer) error {
	dev := device.NewDevice(stream)
	log.Println("Device connected")

	defer func() {
		log.Println("Device disconnected")
		dev.Close()
		registry.Global.Mu.Lock()
		for d, v := range registry.Global.Domains {
			if v == dev {
				registry.Global.Domains[d] = nil
				log.Println("Domain unbound from device:", d)
			}
		}
		registry.Global.Mu.Unlock()
	}()

	for {
		frame, err := stream.Recv()
		if err != nil {
			return err
		}

		switch frame.Type {

		// case tunnelpb.FrameType_FRAME_OPEN:
		// 	domain := strings.ToLower(string(frame.Payload))
		// 	log.Println("BIND request from device for domain:", domain)
		// 	registry.Global.Mu.Lock()
		// 	if _, ok := registry.Global.Domains[domain]; ok {
		// 		registry.Global.Domains[domain] = dev
		// 		log.Println("Domain bound to device:", domain)
		// 	} else {
		// 		log.Println("Bind rejected, domain not registered:", domain)
		// 	}
		// 	registry.Global.Mu.Unlock()

		case tunnelpb.FrameType_FRAME_BIND_REQUEST:
			domain := strings.ToLower(string(frame.Payload))
			log.Println("BIND request from device for domain:", domain)

			registry.Global.Mu.Lock()
			if _, ok := registry.Global.Domains[domain]; ok {
				registry.Global.Domains[domain] = dev
				registry.Global.Mu.Unlock()

				log.Println("Domain bound to device:", domain)
				dev.SendFrame(&tunnelpb.Frame{
					Type:    tunnelpb.FrameType_FRAME_BIND_OK,
					Payload: []byte(domain),
				})
			} else {
				registry.Global.Mu.Unlock()

				log.Println("Bind rejected, domain not registered:", domain)
				dev.SendFrame(&tunnelpb.Frame{
					Type:    tunnelpb.FrameType_FRAME_BIND_REJECTED,
					Payload: []byte(domain),
				})
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
			dev.SendFrame(&tunnelpb.Frame{
				Type: tunnelpb.FrameType_FRAME_PONG,
			})
		}
	}
}
