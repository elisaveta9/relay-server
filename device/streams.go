package device

import (
	"errors"
	"net"
)

var ErrTooManyStreams = errors.New("too many active streams")

func (d *Device) AllocateStreamID() uint32 {
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

func (d *Device) AddStream(id uint32, conn net.Conn) (chan struct{}, error) {
	d.streamsMu.Lock()
	defer d.streamsMu.Unlock()

	if d.maxStreams > 0 && len(d.streams) >= d.maxStreams {
		return nil, ErrTooManyStreams
	}

	ch := make(chan struct{})
	d.streams[id] = conn
	d.streamDone[id] = ch
	return ch, nil
}

func (d *Device) RemoveStream(id uint32) {
	d.streamsMu.Lock()
	defer d.streamsMu.Unlock()

	if c, ok := d.streams[id]; ok {
		_ = c.Close()
		delete(d.streams, id)
	}
	if ch, ok := d.streamDone[id]; ok {
		close(ch)
		delete(d.streamDone, id)
	}
}

func (d *Device) GetClient(id uint32) (net.Conn, bool) {
	d.streamsMu.Lock()
	defer d.streamsMu.Unlock()
	c, ok := d.streams[id]
	return c, ok
}

func (d *Device) Done() <-chan struct{} {
	return d.done
}
