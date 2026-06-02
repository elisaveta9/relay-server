package ingress

import (
	"bufio"
	"context"
	"errors"
	"io"
	"log"
	"net"
	"sync"
	"time"

	"relay/registry"
	"relay/util"

	tunnelpb "relay/proto/tunnel"
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

		if err := dev.SendFrame(ctxClose, &tunnelpb.Frame{
			Type:     tunnelpb.FrameType_FRAME_CLOSE,
			StreamId: streamID,
		}); err != nil {
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
	err = dev.SendFrames(ctxOpen,
		&tunnelpb.Frame{
			Type:     tunnelpb.FrameType_FRAME_OPEN,
			StreamId: streamID,
			Payload:  []byte(sni),
		},
		&tunnelpb.Frame{
			Type:     tunnelpb.FrameType_FRAME_DATA,
			StreamId: streamID,
			Payload:  append([]byte(nil), hello...),
		},
	)
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

			payload := append([]byte(nil), buf[:n]...)

			ctxData, cancelData := context.WithTimeout(context.Background(), sendTimeout)
			err := dev.SendFrame(ctxData, &tunnelpb.Frame{
				Type:     tunnelpb.FrameType_FRAME_DATA,
				StreamId: streamID,
				Payload:  payload,
			})
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
