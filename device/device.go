package device

import (
	"context"
	"errors"
	"expvar"
	"log"
	"net"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	tunnelpb "relay/proto/tunnel"
)

var ErrDeviceClosed = context.Canceled

var (
	ErrDeviceOverloaded = errors.New("device overloaded (queue limit reached)")
)

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

	// Separate control/data queues to prevent DATA bursts from starving control.
	controlCh chan *tunnelpb.Frame
	dataCh    chan *tunnelpb.Frame

	done      chan struct{}
	closeOnce sync.Once
	enqueueMu sync.Mutex

	// maxStreams ограничивает количество одновременных потоков на одно устройство
	maxStreams int

	controlBudget int
	dataBudget    int

	// Пороги отбрасывания данных для кадров DATA
	// Soft: отклонять новые кадры DATA, когда глубина очереди достигает мягкого предела
	// Hfrd: закрывать устройство, когда нагрузка на очередь данных достигает жесткого предела
	dataQueueSoftLimit int
	dataQueueHardLimit int

	queuedControlFrames int64
	queuedDataFrames    int64
	queuedPayloadFrames int64

	streamsMu  sync.Mutex
	streams    map[uint32]net.Conn
	streamDone map[uint32]chan struct{}
	nextID     uint32
}

func NewDevice(stream tunnelpb.TunnelService_TunnelServer, fingerprint string, sessionID string) *Device {
	const (
		defaultMaxStreams    = 128
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

	controlQueueSize := getInt("RELAY_CONTROL_QUEUE_SIZE", defaultControlQSize)
	dataQueueSize := getInt("RELAY_DATA_QUEUE_SIZE", defaultDataQSize)

	controlBudget := getInt("RELAY_CONTROL_BUDGET", defaultControlBudget)
	dataBudget := getInt("RELAY_DATA_BUDGET", defaultDataBudget)

	dataQueueSoftLimit := getInt("RELAY_DATA_QUEUE_SOFT_LIMIT", defaultDataSoftLimit)
	dataQueueHardLimit := getInt("RELAY_DATA_QUEUE_HARD_LIMIT", defaultDataHardLimit)

	if maxStreams <= 0 {
		maxStreams = defaultMaxStreams
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

		controlCh: make(chan *tunnelpb.Frame, controlQueueSize),
		dataCh:    make(chan *tunnelpb.Frame, dataQueueSize),

		done:          make(chan struct{}),
		maxStreams:    maxStreams,
		controlBudget: controlBudget,
		dataBudget:    dataBudget,

		dataQueueSoftLimit: dataQueueSoftLimit,
		dataQueueHardLimit: dataQueueHardLimit,

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

		d.enqueueMu.Lock()
		d.enqueueMu.Unlock()

		// Очистка всех активных потоков при отключении устройства
		d.streamsMu.Lock()
		ids := make([]uint32, 0, len(d.streams))
		for id := range d.streams {
			ids = append(ids, id)
		}
		d.streamsMu.Unlock()

		for _, id := range ids {
			d.RemoveStream(id)
		}
	})
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

	select {
	case <-d.done:
		return ErrDeviceClosed
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	d.enqueueMu.Lock()
	closeAfterReturn := false
	defer func() {
		d.enqueueMu.Unlock()
		if closeAfterReturn {
			d.Close()
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
		if isControlFrame(f.Type) {
			controlCount++
			continue
		}
		dataQueueCount++
		if f.Type == tunnelpb.FrameType_FRAME_DATA {
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
		if isControlFrame(f.Type) {
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

func isControlFrame(t tunnelpb.FrameType) bool {
	switch t {
	case tunnelpb.FrameType_FRAME_PING,
		tunnelpb.FrameType_FRAME_PONG,
		tunnelpb.FrameType_FRAME_BIND_OK,
		tunnelpb.FrameType_FRAME_BIND_REJECTED,
		tunnelpb.FrameType_FRAME_BIND_REVOKED,
		tunnelpb.FrameType_FRAME_UNBIND_OK,
		tunnelpb.FrameType_FRAME_UNBIND_REJECTED:
		return true
	default:
		return false
	}
}

func (d *Device) sendFrame(f *tunnelpb.Frame) error {
	start := time.Now()
	if err := d.stream.Send(f); err != nil {
		log.Println("device send error:", err)
		return err
	}
	latMs := time.Since(start).Milliseconds()
	expGRPCSendLatencyMs.Add(latMs)
	expGRPCSendLatencyCnt.Add(1)
	return nil
}

func (d *Device) drain(ch <-chan *tunnelpb.Frame, budget int, isControl bool) error {
	// Non-blocking: взять до budget frames, если они доступны
	for i := 0; i < budget; i++ {
		select {
		case f := <-ch:
			if isControl {
				atomic.AddInt64(&d.queuedControlFrames, -1)
			} else {
				atomic.AddInt64(&d.queuedDataFrames, -1)
				if f.Type == tunnelpb.FrameType_FRAME_DATA {
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
			if f.Type == tunnelpb.FrameType_FRAME_DATA {
				atomic.AddInt64(&d.queuedPayloadFrames, -1)
			}
			expSendQueueDepth.Add(-1)
		default:
			return
		}
	}
}

func (d *Device) writer() {
	// Взвешенное планирование, сохраняющее целостность кадров (без их отбрасывания)
	for {
		// Быстрое завершение: ограниченная выгрузка
		select {
		case <-d.done:
			_ = d.drain(d.controlCh, d.controlBudget, true)
			_ = d.drain(d.dataCh, d.dataBudget, false)
			d.discardQueued()
			return
		default:
		}

		// Дождаться хотя бы одного кадра любого типа
		select {
		case <-d.done:
			continue
		case f := <-d.controlCh:
			// Jnghfdbnm control frame, а затем — в пределах оставшегося бюджета
			atomic.AddInt64(&d.queuedControlFrames, -1)
			expSendQueueDepth.Add(-1)

			if err := d.sendFrame(f); err != nil {
				d.Close()
				return
			}

			if err := d.drain(d.controlCh, d.controlBudget-1, true); err != nil {
				d.Close()
				return
			}
			_ = d.drain(d.dataCh, d.dataBudget, false)

		case f := <-d.dataCh:
			atomic.AddInt64(&d.queuedDataFrames, -1)
			if f.Type == tunnelpb.FrameType_FRAME_DATA {
				atomic.AddInt64(&d.queuedPayloadFrames, -1)
			}
			expSendQueueDepth.Add(-1)

			if err := d.sendFrame(f); err != nil {
				d.Close()
				return
			}

			if err := d.drain(d.dataCh, d.dataBudget-1, false); err != nil {
				d.Close()
				return
			}
			_ = d.drain(d.controlCh, d.controlBudget, true)
		}
	}
}
