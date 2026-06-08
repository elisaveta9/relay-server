package device

import (
	"context"
	"errors"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"

	tunnelpb "relay/proto/tunnel/v2"

	"google.golang.org/grpc"
)

func newTestDevice(dataQueueSize int, softLimit int, hardLimit int) *Device {
	return &Device{
		Fingerprint:        "test-fingerprint",
		SessionID:          "test-session",
		controlCh:          make(chan *tunnelpb.Frame, 4),
		dataCh:             make(chan *tunnelpb.Frame, dataQueueSize),
		done:               make(chan struct{}),
		writerDone:         make(chan struct{}),
		maxStreams:         2,
		controlBudget:      1,
		dataBudget:         1,
		dataQueueSoftLimit: softLimit,
		dataQueueHardLimit: hardLimit,
		streams:            make(map[uint64]net.Conn),
		streamDone:         make(map[uint64]chan struct{}),
		nextID:             1,
	}
}

type recordingTunnelServer struct {
	grpc.ServerStream
	sent chan *tunnelpb.Frame
}

func (s *recordingTunnelServer) Send(frame *tunnelpb.Frame) error {
	s.sent <- frame
	return nil
}

func (s *recordingTunnelServer) Recv() (*tunnelpb.Frame, error) {
	return nil, io.EOF
}

type blockingTunnelServer struct {
	grpc.ServerStream
	sent         chan *tunnelpb.Frame
	firstStarted chan struct{}
	releaseFirst chan struct{}
	sendCount    atomic.Int32
}

func (s *blockingTunnelServer) Send(frame *tunnelpb.Frame) error {
	if s.sendCount.Add(1) == 1 {
		close(s.firstStarted)
		<-s.releaseFirst
	}
	s.sent <- frame
	return nil
}

func (s *blockingTunnelServer) Recv() (*tunnelpb.Frame, error) {
	return nil, io.EOF
}

func TestSendFrameSoftOverloadRejectsDataOnly(t *testing.T) {
	d := newTestDevice(4, 0, 3)
	defer d.Close()

	err := d.SendFrame(context.Background(), tunnelpb.NewStreamOpenFrame(1, "example.com", "remote"))
	if err != nil {
		t.Fatalf("SendFrame OPEN returned error: %v", err)
	}

	err = d.SendFrame(context.Background(), tunnelpb.NewStreamDataFrame(1, []byte("hello")))
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
		if got.GetStreamOpen() == nil {
			t.Fatalf("queued frame body = %T, want StreamOpen", got.GetBody())
		}
		atomic.AddInt64(&d.queuedDataFrames, -1)
		expSendQueueDepth.Add(-1)
	default:
		t.Fatal("expected OPEN to remain queued")
	}
}

func TestSendFrameHardOverloadClosesDevice(t *testing.T) {
	t.Setenv("RELAY_GOAWAY_OVERLOAD_RETRY_AFTER_SECONDS", "17")

	d := newTestDevice(4, 1, 1)

	if err := d.SendFrame(context.Background(), tunnelpb.NewStreamOpenFrame(1, "example.com", "remote")); err != nil {
		t.Fatalf("SendFrame OPEN returned error: %v", err)
	}

	if err := d.SendFrame(context.Background(), tunnelpb.NewStreamDataFrame(1, []byte("first"))); err != nil {
		t.Fatalf("SendFrame first DATA returned error: %v", err)
	}

	err := d.SendFrame(context.Background(), tunnelpb.NewStreamDataFrame(1, []byte("second")))
	if !errors.Is(err, ErrDeviceOverloaded) {
		t.Fatalf("SendFrame second DATA error = %v, want %v", err, ErrDeviceOverloaded)
	}

	select {
	case <-d.Done():
	case <-time.After(time.Second):
		t.Fatal("device was not closed after hard overload")
	}

	if d.closeFrame == nil {
		t.Fatal("close frame is nil, want GoAway")
	}
	goaway := d.closeFrame.GetGoaway()
	if goaway == nil {
		t.Fatalf("close frame body = %T, want GoAway", d.closeFrame.GetBody())
	}
	if got, want := goaway.GetCode(), tunnelpb.TunnelErrorCode_TUNNEL_ERROR_CODE_SERVER_UNDER_PRESSURE; got != want {
		t.Fatalf("GoAway code = %s, want %s", got, want)
	}
	if !goaway.GetReconnect() {
		t.Fatal("GoAway reconnect = false, want true")
	}
	if got, want := goaway.GetRetryAfterSeconds(), uint32(17); got != want {
		t.Fatalf("GoAway retry_after_seconds = %d, want %d", got, want)
	}
}

func TestSendFrameCloseBypassesPayloadOverload(t *testing.T) {
	d := newTestDevice(4, 1, 1)
	defer d.Close()

	if err := d.SendFrame(context.Background(), tunnelpb.NewStreamDataFrame(1, []byte("first"))); err != nil {
		t.Fatalf("SendFrame DATA returned error: %v", err)
	}

	err := d.SendFrame(context.Background(), tunnelpb.NewStreamCloseFrame(1, tunnelpb.CloseReason_CLOSE_REASON_NORMAL, ""))
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
		tunnelpb.NewStreamOpenFrame(1, "example.com", "remote"),
		tunnelpb.NewStreamDataFrame(1, []byte("hello")),
	)
	if !errors.Is(err, ErrDeviceOverloaded) {
		t.Fatalf("SendFrames OPEN+DATA error = %v, want %v", err, ErrDeviceOverloaded)
	}
	if got := atomic.LoadInt64(&d.queuedDataFrames); got != 0 {
		t.Fatalf("queuedDataFrames = %d, want 0", got)
	}
	select {
	case f := <-d.dataCh:
		t.Fatalf("unexpected queued frame after rejected batch: %T", f.GetBody())
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

	err = d.SendFrame(context.Background(), &tunnelpb.Frame{Body: &tunnelpb.Frame_Ping{Ping: &tunnelpb.Ping{}}})
	if !errors.Is(err, ErrDeviceClosed) {
		t.Fatalf("SendFrame after Close error = %v, want %v", err, ErrDeviceClosed)
	}
}

func TestCloseWithGoAwaySendsTerminalFrame(t *testing.T) {
	stream := &recordingTunnelServer{sent: make(chan *tunnelpb.Frame, 1)}
	d := newTestDevice(4, 2, 4)
	d.stream = stream
	go d.writer()

	d.CloseWithGoAway(
		tunnelpb.TunnelErrorCode_TUNNEL_ERROR_CODE_SERVER_UNDER_PRESSURE,
		"server under pressure",
		true,
		23,
	)

	select {
	case frame := <-stream.sent:
		goaway := frame.GetGoaway()
		if goaway == nil {
			t.Fatalf("sent frame body = %T, want GoAway", frame.GetBody())
		}
		if got, want := goaway.GetRetryAfterSeconds(), uint32(23); got != want {
			t.Fatalf("GoAway retry_after_seconds = %d, want %d", got, want)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for GoAway")
	}
}

func TestCloseWithFrameReasonAndWaitDiscardsQueuedFramesBeforeTerminalFrame(t *testing.T) {
	stream := &blockingTunnelServer{
		sent:         make(chan *tunnelpb.Frame, 3),
		firstStarted: make(chan struct{}),
		releaseFirst: make(chan struct{}),
	}
	d := newTestDevice(4, 2, 4)
	d.stream = stream
	go d.writer()

	if err := d.SendFrame(context.Background(), tunnelpb.NewStreamDataFrame(1, []byte("in-flight"))); err != nil {
		t.Fatalf("queue first stream data: %v", err)
	}
	select {
	case <-stream.firstStarted:
	case <-time.After(time.Second):
		t.Fatal("writer did not start first send")
	}
	if err := d.SendFrame(context.Background(), tunnelpb.NewStreamDataFrame(1, []byte("queued"))); err != nil {
		t.Fatalf("queue second stream data: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	waitErr := make(chan error, 1)
	go func() {
		waitErr <- d.CloseWithFrameReasonAndWait(
			ctx,
			tunnelpb.NewTunnelErrorFrame(
				tunnelpb.TunnelErrorCode_TUNNEL_ERROR_CODE_INVALID_FRAME,
				"invalid frame",
				"",
			),
			"protocol_violation",
		)
	}()
	select {
	case <-d.Done():
	case <-time.After(time.Second):
		t.Fatal("device was not closed")
	}
	close(stream.releaseFirst)

	select {
	case frame := <-stream.sent:
		if got := string(frame.GetStreamData()); got != "in-flight" {
			t.Fatalf("first sent frame = %T %q, want in-flight StreamData", frame.GetBody(), got)
		}
	case <-time.After(time.Second):
		t.Fatal("first frame was not sent")
	}
	select {
	case frame := <-stream.sent:
		if frame.GetError() == nil {
			t.Fatalf("second sent frame body = %T, want TunnelError", frame.GetBody())
		}
	case <-time.After(time.Second):
		t.Fatal("terminal frame was not sent")
	}
	if err := <-waitErr; err != nil {
		t.Fatalf("CloseWithFrameReasonAndWait returned error: %v", err)
	}
	select {
	case frame := <-stream.sent:
		t.Fatalf("unexpected frame after terminal frame: %T", frame.GetBody())
	default:
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

func TestNewDeviceWithLimitsStoresMaxFrameSize(t *testing.T) {
	d := NewDeviceWithLimits(nil, "fingerprint", "session", 4, 12345)
	defer d.Close()

	if got, want := d.MaxFrameSizeBytes(), uint32(12345); got != want {
		t.Fatalf("MaxFrameSizeBytes = %d, want %d", got, want)
	}
}

func TestSendFrameRejectsSerializedFrameAboveLimit(t *testing.T) {
	d := newTestDevice(4, 2, 4)
	d.maxFrameSizeBytes = 6
	defer d.Close()

	err := d.SendFrame(context.Background(), tunnelpb.NewStreamDataFrame(1, []byte("abc")))
	if !errors.Is(err, ErrFrameTooLarge) {
		t.Fatalf("SendFrame error = %v, want %v", err, ErrFrameTooLarge)
	}
	select {
	case frame := <-d.dataCh:
		t.Fatalf("unexpected queued frame: %T", frame.GetBody())
	default:
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
