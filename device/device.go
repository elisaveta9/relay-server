package device

import (
	"context"
	"errors"
	"expvar"
	"fmt"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	tunnelpb "relay/proto/tunnel/v2"

	"google.golang.org/protobuf/proto"
)

var ErrDeviceClosed = context.Canceled

var (
	ErrDeviceOverloaded = errors.New("device overloaded (queue limit reached)")
	ErrFrameTooLarge    = errors.New("frame exceeds negotiated size limit")
)

const defaultGoAwayOverloadRetryAfterSeconds = 30

var (
	expSendQueueDepth = expvar.NewInt("device_send_queue_depth")
	expDroppedFrames  = expvar.NewInt("device_dropped_frames")
	expRejectedFrames = expvar.NewInt("device_rejected_frames")

	expQueueWaitTimeMs    = expvar.NewInt("device_queue_wait_time_ms")
	expQueueWaitTimeCnt   = expvar.NewInt("device_queue_wait_time_count")
	expGRPCSendLatencyMs  = expvar.NewInt("device_grpc_send_latency_ms")
	expGRPCSendLatencyCnt = expvar.NewInt("device_grpc_send_latency_count")
)

type Device struct {
	Fingerprint string

	SessionID string

	stream tunnelpb.TunnelService_TunnelServer

	maxFrameSizeBytes uint32

	supportedFeaturesMu sync.RWMutex
	supportedFeatures   map[string]struct{}

	controlCh chan *tunnelpb.Frame
	dataCh    chan *tunnelpb.Frame

	done       chan struct{}
	writerDone chan struct{}
	closeOnce  sync.Once
	enqueueMu  sync.Mutex

	closeFrame       *tunnelpb.Frame
	lifecycleMu      sync.Mutex
	firstCloseOnce   sync.Once
	firstCloseReason string
	closeReason      string
	writerLastError  string
	terminalSendErr  error

	// maxStreams ограничивает количество одновременных потоков на одно устройство
	maxStreams int

	controlBudget int
	dataBudget    int

	// Пороги отбрасывания данных для кадров DATA
	// Soft: отклонять новые кадры DATA, когда глубина очереди достигает мягкого предела
	// Hard: закрывать устройство, когда нагрузка на очередь данных достигает жесткого предела
	dataQueueSoftLimit int
	dataQueueHardLimit int

	queuedControlFrames int64
	queuedDataFrames    int64
	queuedPayloadFrames int64

	streamsMu  sync.Mutex
	streams    map[uint64]net.Conn
	streamDone map[uint64]chan struct{}
	nextID     uint64

	pendingOpensMu sync.Mutex
	pendingOpens   map[uint64]chan *tunnelpb.StreamOpenResult
}

func NewDevice(stream tunnelpb.TunnelService_TunnelServer, fingerprint string, sessionID string) *Device {
	return newDevice(stream, fingerprint, sessionID, -1, 0)
}

func NewDeviceWithMaxStreams(stream tunnelpb.TunnelService_TunnelServer, fingerprint string, sessionID string, maxStreams int) *Device {
	return newDevice(stream, fingerprint, sessionID, maxStreams, 0)
}

func NewDeviceWithLimits(stream tunnelpb.TunnelService_TunnelServer, fingerprint string, sessionID string, maxStreams int, maxFrameSizeBytes uint32) *Device {
	return newDevice(stream, fingerprint, sessionID, maxStreams, maxFrameSizeBytes)
}

func (d *Device) SetSupportedFeatures(features []string) {
	supported := make(map[string]struct{}, len(features))
	for _, feature := range features {
		feature = strings.TrimSpace(feature)
		if feature != "" {
			supported[feature] = struct{}{}
		}
	}

	d.supportedFeaturesMu.Lock()
	d.supportedFeatures = supported
	d.supportedFeaturesMu.Unlock()
}

func (d *Device) SupportsFeature(feature string) bool {
	d.supportedFeaturesMu.RLock()
	_, ok := d.supportedFeatures[feature]
	d.supportedFeaturesMu.RUnlock()
	return ok
}

func newDevice(stream tunnelpb.TunnelService_TunnelServer, fingerprint string, sessionID string, maxStreamsOverride int, maxFrameSizeBytesOverride uint32) *Device {
	const (
		defaultMaxStreams    = 24
		defaultMaxFrameSize  = 8 * 1024 * 1024
		defaultControlQSize  = 256
		defaultDataQSize     = 1024
		defaultControlBudget = 20
		defaultDataBudget    = 50
		defaultDataSoftLimit = 768
		defaultDataHardLimit = 960
	)

	getInt := func(key string, def int) int {
		v := os.Getenv(key)
		if v == "" {
			return def
		}
		i, err := strconv.Atoi(v)
		if err != nil {
			log.Printf("invalid %s=%q, using default=%d: %v", key, v, def, err)
			return def
		}
		return i
	}

	maxStreams := getInt("RELAY_MAX_STREAMS_PER_DEVICE", defaultMaxStreams)
	maxFrameSizeBytes := getInt("RELAY_MAX_FRAME_SIZE_BYTES", defaultMaxFrameSize)
	controlQueueSize := getInt("RELAY_CONTROL_QUEUE_SIZE", defaultControlQSize)
	dataQueueSize := getInt("RELAY_DATA_QUEUE_SIZE", defaultDataQSize)

	controlBudget := getInt("RELAY_CONTROL_BUDGET", defaultControlBudget)
	dataBudget := getInt("RELAY_DATA_BUDGET", defaultDataBudget)

	dataQueueSoftLimit := getInt("RELAY_DATA_QUEUE_SOFT_LIMIT", defaultDataSoftLimit)
	dataQueueHardLimit := getInt("RELAY_DATA_QUEUE_HARD_LIMIT", defaultDataHardLimit)

	if maxStreams <= 0 {
		maxStreams = defaultMaxStreams
	}
	if maxStreamsOverride >= 0 {
		maxStreams = maxStreamsOverride
	}
	if maxFrameSizeBytes <= 0 {
		maxFrameSizeBytes = defaultMaxFrameSize
	}
	if maxFrameSizeBytesOverride > 0 {
		maxFrameSizeBytes = int(maxFrameSizeBytesOverride)
	}
	if controlQueueSize <= 0 {
		controlQueueSize = defaultControlQSize
	}
	if dataQueueSize <= 0 {
		dataQueueSize = defaultDataQSize
	}
	if controlBudget <= 0 {
		controlBudget = defaultControlBudget
	}
	if dataBudget <= 0 {
		dataBudget = defaultDataBudget
	}
	if dataQueueSoftLimit < 0 {
		dataQueueSoftLimit = defaultDataSoftLimit
	}
	if dataQueueHardLimit < 0 {
		dataQueueHardLimit = defaultDataHardLimit
	}

	if dataQueueHardLimit < dataQueueSoftLimit {
		dataQueueHardLimit = defaultDataHardLimit
		dataQueueSoftLimit = defaultDataSoftLimit
	}

	if dataQueueSoftLimit > dataQueueSize {
		dataQueueSoftLimit = dataQueueSize
	}
	if dataQueueHardLimit > dataQueueSize {
		dataQueueHardLimit = dataQueueSize
	}

	d := &Device{
		Fingerprint: fingerprint,
		SessionID:   sessionID,
		stream:      stream,

		maxFrameSizeBytes: uint32(maxFrameSizeBytes),

		controlCh: make(chan *tunnelpb.Frame, controlQueueSize),
		dataCh:    make(chan *tunnelpb.Frame, dataQueueSize),

		done:          make(chan struct{}),
		writerDone:    make(chan struct{}),
		maxStreams:    maxStreams,
		controlBudget: controlBudget,
		dataBudget:    dataBudget,

		dataQueueSoftLimit: dataQueueSoftLimit,
		dataQueueHardLimit: dataQueueHardLimit,

		streams:    make(map[uint64]net.Conn),
		streamDone: make(map[uint64]chan struct{}),
		nextID:     1,

		pendingOpens: make(map[uint64]chan *tunnelpb.StreamOpenResult),
	}

	go d.writer()
	return d
}

func (d *Device) Close() {
	d.CloseWithReason("server_local_close")
}

func (d *Device) CloseWithReason(reason string) {
	d.CloseWithFrameReason(nil, reason)
}

func (d *Device) CloseWithGoAway(code tunnelpb.TunnelErrorCode, message string, reconnect bool, retryAfterSeconds uint32) {
	d.CloseWithGoAwayReason(code, message, reconnect, retryAfterSeconds, "server_goaway")
}

func (d *Device) CloseWithGoAwayReason(code tunnelpb.TunnelErrorCode, message string, reconnect bool, retryAfterSeconds uint32, reason string) {
	d.CloseWithGoAwayDisconnectReason(code, message, reconnect, retryAfterSeconds, tunnelpb.DisconnectReason_DISCONNECT_REASON_UNSPECIFIED, reason)
}

func (d *Device) CloseWithGoAwayDisconnectReason(code tunnelpb.TunnelErrorCode, message string, reconnect bool, retryAfterSeconds uint32, disconnectReason tunnelpb.DisconnectReason, reason string) {
	d.CloseWithFrameReason(tunnelpb.NewGoAwayFrameWithReason(code, message, reconnect, retryAfterSeconds, disconnectReason), reason)
}

func (d *Device) CloseWithFrame(frame *tunnelpb.Frame) {
	d.CloseWithFrameReason(frame, "server_terminal_frame")
}

func (d *Device) CloseWithFrameReason(frame *tunnelpb.Frame, reason string) {
	d.closeOnce.Do(func() {
		d.MarkFirstCloseReason(reason)
		d.setCloseReason(reason)
		d.closeFrame = frame
		close(d.done)

		d.enqueueMu.Lock()
		d.enqueueMu.Unlock()

		// Очистка всех активных потоков при отключении устройства
		d.streamsMu.Lock()
		ids := make([]uint64, 0, len(d.streams))
		for id := range d.streams {
			ids = append(ids, id)
		}
		d.streamsMu.Unlock()

		for _, id := range ids {
			d.RemoveStream(id)
		}
	})
}

func (d *Device) CloseWithFrameReasonAndWait(ctx context.Context, frame *tunnelpb.Frame, reason string) error {
	d.CloseWithFrameReason(frame, reason)

	select {
	case <-d.writerDone:
		d.lifecycleMu.Lock()
		defer d.lifecycleMu.Unlock()
		return d.terminalSendErr
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (d *Device) CloseReason() string {
	d.lifecycleMu.Lock()
	defer d.lifecycleMu.Unlock()
	return d.closeReason
}

func (d *Device) FirstCloseReason() string {
	d.lifecycleMu.Lock()
	defer d.lifecycleMu.Unlock()
	return d.firstCloseReason
}

func (d *Device) MarkFirstCloseReason(reason string) {
	if reason == "" {
		reason = "unspecified"
	}
	d.firstCloseOnce.Do(func() {
		d.lifecycleMu.Lock()
		d.firstCloseReason = reason
		d.lifecycleMu.Unlock()
		log.Printf("tunnel first close event: fingerprint=%s session=%s reason=%s", d.Fingerprint, d.SessionID, reason)
	})
}

func (d *Device) WriterLastError() string {
	d.lifecycleMu.Lock()
	defer d.lifecycleMu.Unlock()
	return d.writerLastError
}

func (d *Device) setCloseReason(reason string) {
	if reason == "" {
		reason = "unspecified"
	}
	d.lifecycleMu.Lock()
	defer d.lifecycleMu.Unlock()
	d.closeReason = reason
}

func (d *Device) setWriterLastError(err error) {
	if err == nil {
		return
	}
	d.lifecycleMu.Lock()
	defer d.lifecycleMu.Unlock()
	d.writerLastError = err.Error()
}

// TryAdmitStream выполняет предварительную проверку на перегрузку или превышение лимита потока.
// Данная функция не должна ставить кадры в очередь
func (d *Device) TryAdmitStream() bool {
	select {
	case <-d.done:
		return false
	default:
	}

	// Ограничение потоков: разрешаем только при наличии свободной емкости
	d.streamsMu.Lock()
	cur := len(d.streams)
	d.streamsMu.Unlock()
	if cur >= d.maxStreams {
		return false
	}

	// Ограничение очереди: если достигнут или превышен жесткий порог перегрузки по DATA — отклонить
	depth := atomic.LoadInt64(&d.queuedPayloadFrames)
	if depth >= int64(d.dataQueueHardLimit) {
		d.CloseWithGoAwayDisconnectReason(
			tunnelpb.TunnelErrorCode_TUNNEL_ERROR_CODE_SERVER_UNDER_PRESSURE,
			"server under pressure",
			true,
			goAwayOverloadRetryAfterSeconds(),
			tunnelpb.DisconnectReason_DISCONNECT_REASON_SERVER_OVERLOADED,
			"server_overload_admission_rejected",
		)
		return false
	}

	return true
}

func (d *Device) SendFrame(ctx context.Context, f *tunnelpb.Frame) error {
	return d.SendFrames(ctx, f)
}

func (d *Device) SendFrames(ctx context.Context, frames ...*tunnelpb.Frame) error {
	if len(frames) == 0 {
		return nil
	}
	for _, frame := range frames {
		if err := d.validateFrameSize(frame); err != nil {
			expRejectedFrames.Add(1)
			return err
		}
	}

	select {
	case <-d.done:
		return ErrDeviceClosed
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	d.enqueueMu.Lock()
	closeAfterReturn := false
	closeFrameAfterReturn := (*tunnelpb.Frame)(nil)
	defer func() {
		d.enqueueMu.Unlock()
		if closeAfterReturn {
			d.CloseWithFrameReason(closeFrameAfterReturn, "server_overload")
		}
	}()

	select {
	case <-d.done:
		return ErrDeviceClosed
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	controlCount := 0
	dataQueueCount := 0
	payloadDataCount := 0
	for _, f := range frames {
		if tunnelpb.IsControlFrame(f) {
			controlCount++
			continue
		}
		dataQueueCount++
		if tunnelpb.IsStreamDataFrame(f) {
			payloadDataCount++
		}
	}

	if payloadDataCount > 0 {
		depth := atomic.LoadInt64(&d.queuedPayloadFrames)
		projectedDepth := depth + int64(payloadDataCount)
		if depth >= int64(d.dataQueueHardLimit) || projectedDepth > int64(d.dataQueueHardLimit) {
			expRejectedFrames.Add(1)
			log.Printf(
				"device hard overload: fingerprint=%s session=%s payload_depth=%d projected_payload_depth=%d hard_limit=%d",
				d.Fingerprint,
				d.SessionID,
				depth,
				projectedDepth,
				d.dataQueueHardLimit,
			)
			closeAfterReturn = true
			closeFrameAfterReturn = newOverloadGoAwayFrame()
			return ErrDeviceOverloaded
		}
		if depth >= int64(d.dataQueueSoftLimit) || projectedDepth > int64(d.dataQueueSoftLimit) {
			expDroppedFrames.Add(1)
			log.Printf(
				"device soft overload: fingerprint=%s session=%s payload_depth=%d projected_payload_depth=%d soft_limit=%d",
				d.Fingerprint,
				d.SessionID,
				depth,
				projectedDepth,
				d.dataQueueSoftLimit,
			)
			return ErrDeviceOverloaded
		}
	}

	start := time.Now()
	for controlCount > cap(d.controlCh)-len(d.controlCh) || dataQueueCount > cap(d.dataCh)-len(d.dataCh) {
		select {
		case <-d.done:
			return ErrDeviceClosed
		case <-ctx.Done():
			if dataQueueCount > 0 {
				expRejectedFrames.Add(1)
			}
			return ctx.Err()
		case <-time.After(time.Millisecond):
		}
	}

	if controlCount > 0 {
		atomic.AddInt64(&d.queuedControlFrames, int64(controlCount))
	}
	if dataQueueCount > 0 {
		atomic.AddInt64(&d.queuedDataFrames, int64(dataQueueCount))
	}
	if payloadDataCount > 0 {
		atomic.AddInt64(&d.queuedPayloadFrames, int64(payloadDataCount))
	}
	expSendQueueDepth.Add(int64(len(frames)))

	for _, f := range frames {
		if tunnelpb.IsControlFrame(f) {
			d.controlCh <- f
		} else {
			d.dataCh <- f
		}
	}

	waitMs := time.Since(start).Milliseconds()
	expQueueWaitTimeMs.Add(waitMs)
	expQueueWaitTimeCnt.Add(1)
	return nil
}

func newOverloadGoAwayFrame() *tunnelpb.Frame {
	return tunnelpb.NewGoAwayFrameWithReason(
		tunnelpb.TunnelErrorCode_TUNNEL_ERROR_CODE_SERVER_UNDER_PRESSURE,
		"server under pressure",
		true,
		goAwayOverloadRetryAfterSeconds(),
		tunnelpb.DisconnectReason_DISCONNECT_REASON_SERVER_OVERLOADED,
	)
}

func goAwayOverloadRetryAfterSeconds() uint32 {
	return uint32(envPositiveInt("RELAY_GOAWAY_OVERLOAD_RETRY_AFTER_SECONDS", defaultGoAwayOverloadRetryAfterSeconds))
}

func (d *Device) sendFrame(f *tunnelpb.Frame) error {
	if err := d.validateFrameSize(f); err != nil {
		d.MarkFirstCloseReason("send_loop_frame_too_large")
		d.setWriterLastError(err)
		return err
	}
	start := time.Now()
	if err := d.stream.Send(f); err != nil {
		d.MarkFirstCloseReason(sendLoopCloseReason(err))
		d.setWriterLastError(err)
		log.Printf(
			"tunnel stream send loop error: fingerprint=%s session=%s frame=%s err=%v transport_closing=%t connection_reset=%t context_canceled=%t",
			d.Fingerprint,
			d.SessionID,
			frameBodyName(f),
			err,
			isTransportClosingError(err),
			isConnectionResetError(err),
			errors.Is(err, context.Canceled),
		)
		return err
	}
	latMs := time.Since(start).Milliseconds()
	expGRPCSendLatencyMs.Add(latMs)
	expGRPCSendLatencyCnt.Add(1)
	return nil
}

func (d *Device) validateFrameSize(frame *tunnelpb.Frame) error {
	if d.maxFrameSizeBytes == 0 {
		return nil
	}
	size := proto.Size(frame)
	if size > int(d.maxFrameSizeBytes) {
		return fmt.Errorf("%w: size=%d limit=%d", ErrFrameTooLarge, size, d.maxFrameSizeBytes)
	}
	return nil
}

func sendLoopCloseReason(err error) string {
	switch {
	case err == nil:
		return ""
	case isTransportClosingError(err):
		return "send_loop_transport_closing"
	case strings.Contains(strings.ToLower(err.Error()), "code = unavailable"):
		return "send_loop_unavailable"
	case errors.Is(err, context.Canceled):
		return "send_loop_context_canceled"
	case isConnectionResetError(err):
		return "send_loop_connection_reset"
	default:
		return "send_loop_error"
	}
}

func (d *Device) drain(ch <-chan *tunnelpb.Frame, budget int, isControl bool) error {
	// Non-blocking: взять до budget frames, если они доступны
	for i := 0; i < budget; i++ {
		select {
		case <-d.done:
			return nil
		default:
		}

		select {
		case f := <-ch:
			if isControl {
				atomic.AddInt64(&d.queuedControlFrames, -1)
			} else {
				atomic.AddInt64(&d.queuedDataFrames, -1)
				if tunnelpb.IsStreamDataFrame(f) {
					atomic.AddInt64(&d.queuedPayloadFrames, -1)
				}
			}
			expSendQueueDepth.Add(-1)

			if err := d.sendFrame(f); err != nil {
				return err
			}
		default:
			return nil
		}
	}
	return nil
}

func (d *Device) discardQueued() {
	for {
		select {
		case <-d.controlCh:
			atomic.AddInt64(&d.queuedControlFrames, -1)
			expSendQueueDepth.Add(-1)
		case f := <-d.dataCh:
			atomic.AddInt64(&d.queuedDataFrames, -1)
			if tunnelpb.IsStreamDataFrame(f) {
				atomic.AddInt64(&d.queuedPayloadFrames, -1)
			}
			expSendQueueDepth.Add(-1)
		default:
			return
		}
	}
}

func envPositiveInt(key string, def int) int {
	if value := os.Getenv(key); value != "" {
		parsed, err := strconv.Atoi(value)
		if err != nil || parsed <= 0 {
			log.Printf("invalid %s=%q, using default=%d", key, value, def)
			return def
		}
		return parsed
	}
	return def
}

func frameBodyName(f *tunnelpb.Frame) string {
	if f == nil {
		return "nil"
	}
	switch f.GetBody().(type) {
	case *tunnelpb.Frame_StreamData:
		return "stream_data"
	case *tunnelpb.Frame_StreamOpen:
		return "stream_open"
	case *tunnelpb.Frame_StreamClose:
		return "stream_close"
	case *tunnelpb.Frame_StreamReset:
		return "stream_reset"
	case *tunnelpb.Frame_Hello:
		return "hello"
	case *tunnelpb.Frame_Welcome:
		return "welcome"
	case *tunnelpb.Frame_Ping:
		return "ping"
	case *tunnelpb.Frame_Pong:
		return "pong"
	case *tunnelpb.Frame_Goaway:
		return "goaway"
	case *tunnelpb.Frame_Error:
		return "error"
	case *tunnelpb.Frame_BindRequest:
		return "bind_request"
	case *tunnelpb.Frame_BindResult:
		return "bind_result"
	case *tunnelpb.Frame_UnbindRequest:
		return "unbind_request"
	case *tunnelpb.Frame_UnbindResult:
		return "unbind_result"
	case *tunnelpb.Frame_DomainSync:
		return "domain_sync"
	case *tunnelpb.Frame_DomainRevoked:
		return "domain_revoked"
	case *tunnelpb.Frame_DomainVerificationUpdate:
		return "domain_verification_update"
	default:
		return "unknown"
	}
}

func isTransportClosingError(err error) bool {
	return err != nil && strings.Contains(strings.ToLower(err.Error()), "transport is closing")
}

func isConnectionResetError(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "connection reset") || strings.Contains(msg, "forcibly closed")
}

func (d *Device) writer() {
	defer close(d.writerDone)

	// Взвешенное планирование, сохраняющее целостность кадров (без их отбрасывания)
	for {
		// Terminal frame must be the final frame sent for this tunnel.
		select {
		case <-d.done:
			if d.closeFrame != nil && d.stream != nil {
				if err := d.sendFrame(d.closeFrame); err != nil {
					d.lifecycleMu.Lock()
					d.terminalSendErr = err
					d.lifecycleMu.Unlock()
					log.Printf("send terminal close frame failed: fingerprint=%s session=%s err=%v", d.Fingerprint, d.SessionID, err)
				}
			}
			d.discardQueued()
			return
		default:
		}

		// Дождаться хотя бы одного кадра любого типа
		select {
		case <-d.done:
			continue
		case f := <-d.controlCh:
			atomic.AddInt64(&d.queuedControlFrames, -1)
			expSendQueueDepth.Add(-1)

			if err := d.sendFrame(f); err != nil {
				d.CloseWithReason("server_send_loop_error")
				return
			}

			if err := d.drain(d.controlCh, d.controlBudget-1, true); err != nil {
				d.CloseWithReason("server_send_loop_error")
				return
			}
			if err := d.drain(d.dataCh, d.dataBudget, false); err != nil {
				d.CloseWithReason("server_send_loop_error")
				return
			}

		case f := <-d.dataCh:
			atomic.AddInt64(&d.queuedDataFrames, -1)
			if tunnelpb.IsStreamDataFrame(f) {
				atomic.AddInt64(&d.queuedPayloadFrames, -1)
			}
			expSendQueueDepth.Add(-1)

			if err := d.sendFrame(f); err != nil {
				d.CloseWithReason("server_send_loop_error")
				return
			}

			if err := d.drain(d.dataCh, d.dataBudget-1, false); err != nil {
				d.CloseWithReason("server_send_loop_error")
				return
			}
			if err := d.drain(d.controlCh, d.controlBudget, true); err != nil {
				d.CloseWithReason("server_send_loop_error")
				return
			}
		}
	}
}
