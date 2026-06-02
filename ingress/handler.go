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
	defer conn.Close()
	remote := conn.RemoteAddr().String()

	const (
		readTimeout  = 30 * time.Second
		writeTimeout = 30 * time.Second
		sendTimeout  = 200 * time.Millisecond
	)

	_ = conn.SetReadDeadline(time.Now().Add(readTimeout))

	br := bufio.NewReaderSize(conn, maxClientHelloLen+maxTLSRecordLen)
	sni, hello, err := peekClientHello(br)
	if err != nil {
		log.Printf("ingress rejected: remote=%s reason=peek_client_hello_failed err=%v", remote, err)
		return
	}

	log.Printf("Client SNI: %s remote=%s", sni, remote)

	dev, _ := registry.Global.Get(sni)
	if dev == nil {
		log.Printf("ingress rejected: remote=%s sni=%q reason=no_device_bound", remote, sni)
		_ = conn.SetWriteDeadline(time.Now().Add(writeTimeout))
		_, _ = conn.Write([]byte("HTTP/1.1 503 No device\r\n\r\n"))
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
		_ = conn.SetWriteDeadline(time.Now().Add(writeTimeout))
		_, _ = conn.Write([]byte("HTTP/1.1 503 Busy\r\nConnection: close\r\n\r\n"))
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
		_ = conn.SetWriteDeadline(time.Now().Add(writeTimeout))
		_, _ = conn.Write([]byte("HTTP/1.1 503 Busy\r\nConnection: close\r\n\r\n"))
		return
	}

	var removeOnce sync.Once
	removeStream := func() { removeOnce.Do(func() { dev.RemoveStream(streamID) }) }
	sendClose := func() {
		ctxClose, cancelClose := context.WithTimeout(context.Background(), sendTimeout)
		defer cancelClose()

		_ = dev.SendFrame(ctxClose, &tunnelpb.Frame{
			Type:     tunnelpb.FrameType_FRAME_CLOSE,
			StreamId: streamID,
		})
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
		_ = conn.SetWriteDeadline(time.Now().Add(writeTimeout))
		_, _ = conn.Write([]byte("HTTP/1.1 503 Busy\r\nConnection: close\r\n\r\n"))
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
	_ = conn.SetReadDeadline(time.Time{})

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
