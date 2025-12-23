package device

import (
	"net"
)

func (d *Device) AllocateStreamID() uint32 {
	d.streamsMu.Lock()
	defer d.streamsMu.Unlock()

	id := d.nextID
	d.nextID++
	return id
}

func (d *Device) AddStream(id uint32, conn net.Conn) chan struct{} {
	d.streamsMu.Lock()
	defer d.streamsMu.Unlock()

	ch := make(chan struct{})
	d.streams[id] = conn
	d.streamDone[id] = ch
	return ch
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
