package ingress

import (
	"log"
	"net"

	"relay/registry"
	"relay/util"

	tunnelpb "relay/proto/tunnel"
)

func handleClientTCP(conn net.Conn) {
	defer conn.Close()

	sni, hello, err := peekClientHello(conn)
	if err != nil {
		log.Println("peek failed:", err)
		return
	}

	log.Println("Client SNI:", sni)

	registry.Global.Mu.Lock()
	dev := registry.Global.Domains[sni]
	log.Println("Known domains:", util.Keys(registry.Global.Domains))
	registry.Global.Mu.Unlock()

	if dev == nil {
		log.Println("No device bound for domain:", sni)
		conn.Write([]byte("HTTP/1.1 503 No device\r\n\r\n"))
		return
	}

	streamID := dev.AllocateStreamID()
	done := dev.AddStream(streamID, conn)

	log.Printf("Client [%s] -> device (stream %d)\n", sni, streamID)

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

	go func() {
		buf := util.BufPool.Get().([]byte)
		defer util.BufPool.Put(buf)

		for {
			n, err := conn.Read(buf)
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
