package device

import (
	"context"
	"errors"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"

	tunnelpb "relay/proto/tunnel"
)

func newTestDevice(dataQueueSize int, softLimit int, hardLimit int) *Device {
	return &Device{
		Fingerprint:        "test-fingerprint",
		SessionID:          "test-session",
		controlCh:          make(chan *tunnelpb.Frame, 4),
		dataCh:             make(chan *tunnelpb.Frame, dataQueueSize),
		done:               make(chan struct{}),
		maxStreams:         2,
		controlBudget:      1,
		dataBudget:         1,
		dataQueueSoftLimit: softLimit,
		dataQueueHardLimit: hardLimit,
		streams:            make(map[uint32]net.Conn),
		streamDone:         make(map[uint32]chan struct{}),
		nextID:             1,
	}
}

func TestSendFrameSoftOverloadRejectsDataOnly(t *testing.T) {
	d := newTestDevice(4, 0, 3)
	defer d.Close()

	err := d.SendFrame(context.Background(), &tunnelpb.Frame{
		Type:     tunnelpb.FrameType_FRAME_OPEN,
		StreamId: 1,
	})
	if err != nil {
		t.Fatalf("SendFrame OPEN returned error: %v", err)
	}

	err = d.SendFrame(context.Background(), &tunnelpb.Frame{
		Type:     tunnelpb.FrameType_FRAME_DATA,
		StreamId: 1,
		Payload:  []byte("hello"),
	})
	if !errors.Is(err, ErrDeviceOverloaded) {
		t.Fatalf("SendFrame DATA error = %v, want %v", err, ErrDeviceOverloaded)
	}
	if got := atomic.LoadInt64(&d.queuedPayloadFrames); got != 0 {
		t.Fatalf("queuedPayloadFrames = %d, want 0", got)
	}
	if got := atomic.LoadInt64(&d.queuedDataFrames); got != 1 {
		t.Fatalf("queuedDataFrames = %d, want 1 for OPEN", got)
	}
	select {
	case got := <-d.dataCh:
		if got.Type != tunnelpb.FrameType_FRAME_OPEN {
			t.Fatalf("queued frame type = %s, want FRAME_OPEN", got.Type)
		}
		atomic.AddInt64(&d.queuedDataFrames, -1)
		expSendQueueDepth.Add(-1)
	default:
		t.Fatal("expected OPEN to remain queued")
	}
}

func TestSendFrameHardOverloadClosesDevice(t *testing.T) {
	d := newTestDevice(4, 1, 1)

	if err := d.SendFrame(context.Background(), &tunnelpb.Frame{
		Type:     tunnelpb.FrameType_FRAME_OPEN,
		StreamId: 1,
	}); err != nil {
		t.Fatalf("SendFrame OPEN returned error: %v", err)
	}

	if err := d.SendFrame(context.Background(), &tunnelpb.Frame{
		Type:     tunnelpb.FrameType_FRAME_DATA,
		StreamId: 1,
		Payload:  []byte("first"),
	}); err != nil {
		t.Fatalf("SendFrame first DATA returned error: %v", err)
	}

	err := d.SendFrame(context.Background(), &tunnelpb.Frame{
		Type:     tunnelpb.FrameType_FRAME_DATA,
		StreamId: 1,
		Payload:  []byte("second"),
	})
	if !errors.Is(err, ErrDeviceOverloaded) {
		t.Fatalf("SendFrame second DATA error = %v, want %v", err, ErrDeviceOverloaded)
	}

	select {
	case <-d.Done():
	case <-time.After(time.Second):
		t.Fatal("device was not closed after hard overload")
	}
}

func TestSendFrameCloseBypassesPayloadOverload(t *testing.T) {
	d := newTestDevice(4, 1, 1)
	defer d.Close()

	if err := d.SendFrame(context.Background(), &tunnelpb.Frame{
		Type:     tunnelpb.FrameType_FRAME_DATA,
		StreamId: 1,
		Payload:  []byte("first"),
	}); err != nil {
		t.Fatalf("SendFrame DATA returned error: %v", err)
	}

	err := d.SendFrame(context.Background(), &tunnelpb.Frame{
		Type:     tunnelpb.FrameType_FRAME_CLOSE,
		StreamId: 1,
	})
	if err != nil {
		t.Fatalf("SendFrame CLOSE returned error: %v", err)
	}

	if got := atomic.LoadInt64(&d.queuedPayloadFrames); got != 1 {
		t.Fatalf("queuedPayloadFrames = %d, want 1", got)
	}
	if got := atomic.LoadInt64(&d.queuedDataFrames); got != 2 {
		t.Fatalf("queuedDataFrames = %d, want 2 for DATA+CLOSE", got)
	}
}

func TestSendFramesRejectsOpenAndFirstDataTogether(t *testing.T) {
	d := newTestDevice(4, 0, 3)
	defer d.Close()

	err := d.SendFrames(context.Background(),
		&tunnelpb.Frame{
			Type:     tunnelpb.FrameType_FRAME_OPEN,
			StreamId: 1,
		},
		&tunnelpb.Frame{
			Type:     tunnelpb.FrameType_FRAME_DATA,
			StreamId: 1,
			Payload:  []byte("hello"),
		},
	)
	if !errors.Is(err, ErrDeviceOverloaded) {
		t.Fatalf("SendFrames OPEN+DATA error = %v, want %v", err, ErrDeviceOverloaded)
	}
	if got := atomic.LoadInt64(&d.queuedDataFrames); got != 0 {
		t.Fatalf("queuedDataFrames = %d, want 0", got)
	}
	select {
	case f := <-d.dataCh:
		t.Fatalf("unexpected queued frame after rejected batch: %s", f.Type)
	default:
	}
}

func TestCloseClosesStreamsAndRejectsSend(t *testing.T) {
	d := newTestDevice(4, 2, 4)
	client, server := net.Pipe()
	defer closeTestConn(t, client, "client pipe")
	defer closeTestConn(t, server, "server pipe")

	done, err := d.AddStream(1, server)
	if err != nil {
		t.Fatalf("AddStream returned error: %v", err)
	}

	d.Close()

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("stream done channel was not closed")
	}

	if _, ok := d.GetClient(1); ok {
		t.Fatal("stream still registered after Close")
	}

	err = d.SendFrame(context.Background(), &tunnelpb.Frame{
		Type: tunnelpb.FrameType_FRAME_PING,
	})
	if !errors.Is(err, ErrDeviceClosed) {
		t.Fatalf("SendFrame after Close error = %v, want %v", err, ErrDeviceClosed)
	}
}

func TestAddStreamEnforcesLimit(t *testing.T) {
	d := newTestDevice(4, 2, 4)
	defer d.Close()

	c1, s1 := net.Pipe()
	defer closeTestConn(t, c1, "client pipe 1")
	defer closeTestConn(t, s1, "server pipe 1")
	c2, s2 := net.Pipe()
	defer closeTestConn(t, c2, "client pipe 2")
	defer closeTestConn(t, s2, "server pipe 2")
	c3, s3 := net.Pipe()
	defer closeTestConn(t, c3, "client pipe 3")
	defer closeTestConn(t, s3, "server pipe 3")

	if _, err := d.AddStream(1, s1); err != nil {
		t.Fatalf("AddStream first stream returned error: %v", err)
	}
	if _, err := d.AddStream(2, s2); err != nil {
		t.Fatalf("AddStream second stream returned error: %v", err)
	}
	if _, err := d.AddStream(3, s3); !errors.Is(err, ErrTooManyStreams) {
		t.Fatalf("AddStream third stream error = %v, want %v", err, ErrTooManyStreams)
	}
}

func closeTestConn(t *testing.T, conn net.Conn, name string) {
	t.Helper()

	if err := conn.Close(); err != nil &&
		!errors.Is(err, net.ErrClosed) &&
		!errors.Is(err, io.ErrClosedPipe) {
		t.Errorf("close %s: %v", name, err)
	}
}
