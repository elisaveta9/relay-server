package device

import (
	"log"
	"net"
	"sync"

	tunnelpb "relay/proto/tunnel"
)

type Device struct {
	stream    tunnelpb.TunnelService_TunnelServer
	sendCh    chan *tunnelpb.Frame
	done      chan struct{}
	closeOnce sync.Once

	streamsMu  sync.Mutex
	streams    map[uint32]net.Conn
	streamDone map[uint32]chan struct{}
	nextID     uint32
}

func NewDevice(stream tunnelpb.TunnelService_TunnelServer) *Device {
	d := &Device{
		stream:     stream,
		sendCh:     make(chan *tunnelpb.Frame, 128),
		done:       make(chan struct{}),
		streams:    make(map[uint32]net.Conn),
		streamDone: make(map[uint32]chan struct{}),
		nextID:     1,
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
	case d.sendCh <- f:
	case <-d.done:
	default:
		log.Println("device backpressure: drop frame")
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
