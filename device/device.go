package device

import (
	"log"
	"net"
	"sync"

	tunnelpb "relay/proto/tunnel"
)

type Device struct {
	Fingerprint string
	SessionID   string

	stream    tunnelpb.TunnelService_TunnelServer
	sendCh    chan *tunnelpb.Frame
	done      chan struct{}
	closeOnce sync.Once

	streamsMu  sync.Mutex
	streams    map[uint32]net.Conn
	streamDone map[uint32]chan struct{}
	nextID     uint32
}

func NewDevice(stream tunnelpb.TunnelService_TunnelServer, fingerprint string, sessionID string) *Device {
	d := &Device{
		Fingerprint: fingerprint,
		SessionID:   sessionID,
		stream:      stream,
		sendCh:      make(chan *tunnelpb.Frame, 128),
		done:        make(chan struct{}),
		streams:     make(map[uint32]net.Conn),
		streamDone:  make(map[uint32]chan struct{}),
		nextID:      1,
	}

	go d.writer()
	return d
}

func (d *Device) Close() {
	d.closeOnce.Do(func() {
		close(d.done)
	})
}

func (d *Device) SendFrame(f *tunnelpb.Frame) {
	select {
	case <-d.done:
		return
	case d.sendCh <- f:
	}
}

func (d *Device) writer() {
	for {
		select {
		case f := <-d.sendCh:
			if err := d.stream.Send(f); err != nil {
				log.Println("device send error:", err)
				d.Close()
				return
			}
		case <-d.done:
			return
		}
	}
}
