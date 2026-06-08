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
		readTimeout  = 30 * time.Second
		writeTimeout = 30 * time.Second
		sendTimeout  = 200 * time.Millisecond
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
		writeHTTPReject(conn, remote, writeTimeout, "no_device_bound", []byte("HTTP/1.1 503 No device\r\n\r\n"))
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
		writeHTTPReject(conn, remote, writeTimeout, "device_admission_rejected", []byte("HTTP/1.1 503 Busy\r\nConnection: close\r\n\r\n"))
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
		writeHTTPReject(conn, remote, writeTimeout, "add_stream_failed", []byte("HTTP/1.1 503 Busy\r\nConnection: close\r\n\r\n"))
		return
	}

	var removeOnce sync.Once
	removeStream := func() { removeOnce.Do(func() { dev.RemoveStream(streamID) }) }
	sendClose := func() {
		ctxClose, cancelClose := context.WithTimeout(context.Background(), sendTimeout)
		defer cancelClose()

		if err := dev.SendFrame(ctxClose, tunnelpb.NewStreamCloseFrame(streamID, tunnelpb.CloseReason_CLOSE_REASON_LOCAL_CLOSED, "")); err != nil {
			log.Printf("send close frame failed: remote=%s sni=%q stream=%d err=%v", remote, sni, streamID, err)
		}
	}

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
		writeHTTPReject(conn, remote, writeTimeout, "open_stream_send_failed", []byte("HTTP/1.1 503 Busy\r\nConnection: close\r\n\r\n"))
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
		sendClose()
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
		sendClose()
		removeStream()
		return
	}

	go func() {
		buf := util.BufPool.Get().([]byte)
		defer util.BufPool.Put(buf)

		for {
			n, rerr := br.Read(buf)
			if rerr != nil {
				sendClose()

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
				sendClose()
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

func writeHTTPReject(conn net.Conn, remote string, timeout time.Duration, reason string, body []byte) {
	if err := conn.SetWriteDeadline(time.Now().Add(timeout)); err != nil {
		log.Printf("set write deadline failed: remote=%s reason=%s err=%v", remote, reason, err)
		return
	}
	if _, err := conn.Write(body); err != nil {
		log.Printf("write rejection response failed: remote=%s reason=%s err=%v", remote, reason, err)
	}
}

func closeConnLogged(conn net.Conn, label string, remote string) {
	if err := conn.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
		log.Printf("close %s failed: remote=%s err=%v", label, remote, err)
	}
}
