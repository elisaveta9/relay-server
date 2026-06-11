package ingress

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"time"

	"relay/registry"
	"relay/util"

	tunnelpb "relay/proto/tunnel/v2"

	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
)

func handleClientTCP(conn net.Conn) {
	remote := conn.RemoteAddr().String()
	defer closeConnLogged(conn, "ingress client", remote)

	const (
		readTimeout       = 30 * time.Second
		sendTimeout       = 200 * time.Millisecond
		openResultTimeout = 5 * time.Second
	)

	if err := conn.SetReadDeadline(time.Now().Add(readTimeout)); err != nil {
		log.Printf("ingress rejected: remote=%s reason=set_read_deadline_failed err=%v", remote, err)
		return
	}

	br := bufio.NewReaderSize(conn, maxClientHelloLen+maxTLSRecordLen)
	sni, hello, err := peekClientHello(br)
	if err != nil {
		log.Printf("ingress rejected: remote=%s reason=peek_client_hello_failed err=%v", remote, err)
		return
	}

	log.Printf("Client SNI: %s remote=%s", sni, remote)

	dev, bound := registry.Global.Get(sni)
	if !bound || dev == nil {
		log.Printf("ingress rejected: remote=%s sni=%q reason=no_device_bound", remote, sni)
		return
	}

	if !dev.TryAdmitStream() {
		log.Printf(
			"ingress rejected: remote=%s sni=%q reason=device_admission_rejected fingerprint=%s session=%s",
			remote,
			sni,
			dev.Fingerprint,
			dev.SessionID,
		)
		return
	}

	streamID := dev.AllocateStreamID()
	done, err := dev.AddStream(streamID, conn)
	if err != nil {
		log.Printf(
			"ingress rejected: remote=%s sni=%q reason=add_stream_failed fingerprint=%s session=%s stream=%d err=%v",
			remote,
			sni,
			dev.Fingerprint,
			dev.SessionID,
			streamID,
			err,
		)
		return
	}

	var removeOnce sync.Once
	removeStream := func() { removeOnce.Do(func() { dev.RemoveStream(streamID) }) }
	sendClose := func(reason tunnelpb.CloseReason, message string) {
		ctxClose, cancelClose := context.WithTimeout(context.Background(), sendTimeout)
		defer cancelClose()

		if err := dev.SendFrame(ctxClose, tunnelpb.NewStreamCloseFrame(streamID, reason, message)); err != nil {
			log.Printf("send close frame failed: remote=%s sni=%q stream=%d err=%v", remote, sni, streamID, err)
		}
	}

	openResultCh, err := dev.RegisterPendingOpen(streamID)
	if err != nil {
		log.Printf(
			"ingress rejected: remote=%s sni=%q reason=register_pending_open_failed fingerprint=%s session=%s stream=%d err=%v",
			remote,
			sni,
			dev.Fingerprint,
			dev.SessionID,
			streamID,
			err,
		)
		removeStream()
		return
	}
	defer dev.CancelPendingOpen(streamID)

	log.Printf(
		"Client [%s] -> device fingerprint=%s session=%s stream=%d\n",
		sni,
		dev.Fingerprint,
		dev.SessionID,
		streamID,
	)

	ctxOpen, cancelOpen := context.WithTimeout(context.Background(), sendTimeout)
	err = dev.SendFrame(ctxOpen, tunnelpb.NewStreamOpenFrame(streamID, sni, remote))
	cancelOpen()
	if err != nil {
		log.Printf(
			"ingress rejected: remote=%s sni=%q reason=open_stream_send_failed fingerprint=%s session=%s stream=%d err=%v",
			remote,
			sni,
			dev.Fingerprint,
			dev.SessionID,
			streamID,
			err,
		)
		removeStream()
		return
	}

	openTimer := time.NewTimer(openResultTimeout)
	defer openTimer.Stop()

	select {
	case result := <-openResultCh:
		if result == nil || !result.GetSuccess() {
			code := tunnelpb.TunnelErrorCode_TUNNEL_ERROR_CODE_UNSPECIFIED
			message := ""
			if result != nil {
				code = result.GetErrorCode()
				message = result.GetMessage()
			}
			log.Printf(
				"ingress rejected: remote=%s sni=%q reason=device_stream_open_failed fingerprint=%s session=%s stream=%d code=%s message=%q",
				remote,
				sni,
				dev.Fingerprint,
				dev.SessionID,
				streamID,
				code,
				message,
			)
			removeStream()
			return
		}
	case <-openTimer.C:
		log.Printf(
			"ingress rejected: remote=%s sni=%q reason=stream_open_result_timeout fingerprint=%s session=%s stream=%d timeout=%s",
			remote,
			sni,
			dev.Fingerprint,
			dev.SessionID,
			streamID,
			openResultTimeout,
		)
		sendClose(tunnelpb.CloseReason_CLOSE_REASON_ERROR, "stream open result timeout")
		removeStream()
		return
	case <-done:
		log.Printf(
			"ingress rejected: remote=%s sni=%q reason=stream_closed_before_open_result fingerprint=%s session=%s stream=%d",
			remote,
			sni,
			dev.Fingerprint,
			dev.SessionID,
			streamID,
		)
		return
	case <-dev.Done():
		log.Printf(
			"ingress rejected: remote=%s sni=%q reason=device_closed_before_open_result fingerprint=%s session=%s stream=%d",
			remote,
			sni,
			dev.Fingerprint,
			dev.SessionID,
			streamID,
		)
		removeStream()
		return
	}

	ctxHello, cancelHello := context.WithTimeout(context.Background(), sendTimeout)
	err = sendStreamDataChunks(ctxHello, dev, streamID, hello, dev.MaxFrameSizeBytes())
	cancelHello()
	if err != nil {
		log.Printf(
			"ingress rejected: remote=%s sni=%q reason=client_hello_send_failed fingerprint=%s session=%s stream=%d max_frame_size_bytes=%d err=%v",
			remote,
			sni,
			dev.Fingerprint,
			dev.SessionID,
			streamID,
			dev.MaxFrameSizeBytes(),
			err,
		)
		sendClose(tunnelpb.CloseReason_CLOSE_REASON_ERROR, "client hello send failed")
		removeStream()
		return
	}

	if len(hello) > 0 {
		if _, err := br.Discard(len(hello)); err != nil {
			log.Println("discard hello failed:", err)
			removeStream()
			return
		}
	}
	if err := conn.SetReadDeadline(time.Time{}); err != nil {
		log.Printf("clear read deadline failed: remote=%s sni=%q stream=%d err=%v", remote, sni, streamID, err)
		sendClose(tunnelpb.CloseReason_CLOSE_REASON_ERROR, "clear client read deadline failed")
		removeStream()
		return
	}

	go func() {
		buf := util.BufPool.Get().([]byte)
		defer util.BufPool.Put(buf)

		for {
			n, rerr := br.Read(buf)
			if rerr != nil {
				sendClose(tunnelpb.CloseReason_CLOSE_REASON_LOCAL_CLOSED, "")

				if errors.Is(rerr, io.EOF) {

				} else {
					log.Println("tunnel read ended:", rerr)
				}
				removeStream()
				return
			}

			ctxData, cancelData := context.WithTimeout(context.Background(), sendTimeout)
			err := sendStreamDataChunks(ctxData, dev, streamID, buf[:n], dev.MaxFrameSizeBytes())
			cancelData()

			if err != nil {
				sendClose(tunnelpb.CloseReason_CLOSE_REASON_ERROR, "client data send failed")
				removeStream()
				return
			}
		}
	}()

	select {
	case <-done:
	case <-dev.Done():
	}

	removeStream()
}

type streamDataSender interface {
	SendFrame(context.Context, *tunnelpb.Frame) error
}

func sendStreamDataChunks(ctx context.Context, sender streamDataSender, streamID uint64, payload []byte, maxFrameSizeBytes uint32) error {
	if len(payload) == 0 {
		return nil
	}

	maxPayloadSize := len(payload)
	if maxFrameSizeBytes > 0 {
		maxPayloadSize = maxStreamDataPayloadSize(streamID, maxFrameSizeBytes)
		if maxPayloadSize <= 0 {
			return fmt.Errorf("max frame size %d is too small for stream data", maxFrameSizeBytes)
		}
	}

	for len(payload) > 0 {
		chunkSize := maxPayloadSize
		if chunkSize > len(payload) {
			chunkSize = len(payload)
		}

		chunk := append([]byte(nil), payload[:chunkSize]...)
		frame := tunnelpb.NewStreamDataFrame(streamID, chunk)
		if maxFrameSizeBytes > 0 && proto.Size(frame) > int(maxFrameSizeBytes) {
			return fmt.Errorf("stream data frame exceeds max size %d", maxFrameSizeBytes)
		}
		if err := sender.SendFrame(ctx, frame); err != nil {
			return err
		}
		payload = payload[chunkSize:]
	}

	return nil
}

func maxStreamDataPayloadSize(streamID uint64, maxFrameSizeBytes uint32) int {
	limit := int(maxFrameSizeBytes)
	if limit <= 0 {
		return 0
	}

	baseSize := proto.Size(&tunnelpb.Frame{StreamId: streamID})
	low, high := 0, limit
	for low < high {
		mid := low + (high-low+1)/2
		size := baseSize + protowire.SizeTag(10) + protowire.SizeBytes(mid)
		if size <= limit {
			low = mid
		} else {
			high = mid - 1
		}
	}
	return low
}

func closeConnLogged(conn net.Conn, label string, remote string) {
	if err := conn.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
		log.Printf("close %s failed: remote=%s err=%v", label, remote, err)
	}
}
