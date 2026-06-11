package device

import (
	"errors"
	"log"
	"net"

	tunnelpb "relay/proto/tunnel/v2"
)

var (
	ErrTooManyStreams      = errors.New("too many active streams")
	ErrStreamOpenIsPending = errors.New("stream open result is already pending")
)

func (d *Device) AllocateStreamID() uint64 {
	d.streamsMu.Lock()
	defer d.streamsMu.Unlock()

	for {
		id := d.nextID
		d.nextID++

		if _, exists := d.streams[id]; !exists {
			return id
		}
	}
}

func (d *Device) AddStream(id uint64, conn net.Conn) (chan struct{}, error) {
	d.streamsMu.Lock()
	defer d.streamsMu.Unlock()

	if d.maxStreams >= 0 && len(d.streams) >= d.maxStreams {
		return nil, ErrTooManyStreams
	}

	ch := make(chan struct{})
	d.streams[id] = conn
	d.streamDone[id] = ch
	return ch, nil
}

func (d *Device) RemoveStream(id uint64) {
	d.streamsMu.Lock()
	defer d.streamsMu.Unlock()

	if c, ok := d.streams[id]; ok {
		if err := c.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			log.Printf("close device stream failed: fingerprint=%s session=%s stream=%d err=%v", d.Fingerprint, d.SessionID, id, err)
		}
		delete(d.streams, id)
	}
	if ch, ok := d.streamDone[id]; ok {
		close(ch)
		delete(d.streamDone, id)
	}
}

func (d *Device) GetClient(id uint64) (net.Conn, bool) {
	d.streamsMu.Lock()
	defer d.streamsMu.Unlock()
	c, ok := d.streams[id]
	return c, ok
}

func (d *Device) RegisterPendingOpen(id uint64) (<-chan *tunnelpb.StreamOpenResult, error) {
	d.pendingOpensMu.Lock()
	defer d.pendingOpensMu.Unlock()

	if _, exists := d.pendingOpens[id]; exists {
		return nil, ErrStreamOpenIsPending
	}
	if d.pendingOpens == nil {
		d.pendingOpens = make(map[uint64]chan *tunnelpb.StreamOpenResult)
	}

	ch := make(chan *tunnelpb.StreamOpenResult, 1)
	d.pendingOpens[id] = ch
	return ch, nil
}

func (d *Device) CancelPendingOpen(id uint64) {
	d.pendingOpensMu.Lock()
	delete(d.pendingOpens, id)
	d.pendingOpensMu.Unlock()
}

func (d *Device) ResolvePendingOpen(id uint64, result *tunnelpb.StreamOpenResult) bool {
	d.pendingOpensMu.Lock()
	ch, exists := d.pendingOpens[id]
	if exists {
		delete(d.pendingOpens, id)
	}
	d.pendingOpensMu.Unlock()

	if !exists {
		return false
	}

	ch <- result
	return true
}

func (d *Device) MaxFrameSizeBytes() uint32 {
	return d.maxFrameSizeBytes
}

func (d *Device) Done() <-chan struct{} {
	return d.done
}
