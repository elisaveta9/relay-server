package ingress

import (
	"bufio"
	"log"
	"net"

	"relay/registry"
	"relay/util"

	tunnelpb "relay/proto/tunnel"
)

func handleClientTCP(conn net.Conn) {
	defer conn.Close()

	br := bufio.NewReader(conn)
	sni, hello, err := peekClientHello(br)
	if err != nil {
		log.Println("peek failed:", err)
		return
	}

	log.Println("Client SNI:", sni)

	dev, _ := registry.Global.Get(sni)

	if dev == nil {
		log.Println("No device bound for domain:", sni)
		conn.Write([]byte("HTTP/1.1 503 No device\r\n\r\n"))
		return
	}

	streamID := dev.AllocateStreamID()
	done := dev.AddStream(streamID, conn)

	log.Printf(
		"Client [%s] -> device fingerprint=%s session=%s stream=%d\n",
		sni,
		dev.Fingerprint,
		dev.SessionID,
		streamID,
	)

	dev.SendFrame(&tunnelpb.Frame{
		Type:     tunnelpb.FrameType_FRAME_OPEN,
		StreamId: streamID,
		Payload:  []byte(sni),
	})

	dev.SendFrame(&tunnelpb.Frame{
		Type:     tunnelpb.FrameType_FRAME_DATA,
		StreamId: streamID,
		Payload:  hello,
	})

	if len(hello) > 0 {
		if _, err := br.Discard(len(hello)); err != nil {
			log.Println("discard hello failed:", err)
			return
		}
	}

	go func() {
		buf := util.BufPool.Get().([]byte)
		defer util.BufPool.Put(buf)

		for {
			n, err := br.Read(buf)
			if err != nil {
				dev.SendFrame(&tunnelpb.Frame{
					Type:     tunnelpb.FrameType_FRAME_CLOSE,
					StreamId: streamID,
				})
				dev.RemoveStream(streamID)
				return
			}

			dev.SendFrame(&tunnelpb.Frame{
				Type:     tunnelpb.FrameType_FRAME_DATA,
				StreamId: streamID,
				Payload:  append([]byte(nil), buf[:n]...),
			})
		}
	}()

	select {
	case <-done:
	case <-dev.Done():
	}

	dev.RemoveStream(streamID)

}
