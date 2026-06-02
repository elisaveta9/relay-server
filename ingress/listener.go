package ingress

import (
	"log"
	"net"
	"os"
	"strconv"
)

// ingressSem ограничивает количество одновременно обрабатываемых TCP-соединений
// Размер должен быть подобран с учетом доступных ресурсов RAM и CPU
var ingressSem = func() chan struct{} {
	// fallback
	limit := 512
	if v := getenvInt("RELAY_INGRESS_MAX_CONNS"); v > 0 {
		limit = v
	}
	return make(chan struct{}, limit)
}()

func getenvInt(key string) int {
	if val := os.Getenv(key); val != "" {
		if n, err := strconv.Atoi(val); err == nil && n > 0 {
			return n
		}
	}
	return 0
}

func Listen(addr string) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatal(err)
	}
	log.Println("HTTPS passthrough listening on", addr)

	for {
		c, err := ln.Accept()
		if err != nil {
			log.Println("accept error:", err)
			continue
		}

		select {
		case ingressSem <- struct{}{}:

		default:
			log.Printf("ingress rejected: remote=%s reason=max_connections limit=%d", c.RemoteAddr(), cap(ingressSem))
			if err := c.Close(); err != nil {
				log.Printf("close rejected ingress connection failed: remote=%s err=%v", c.RemoteAddr(), err)
			}
			continue
		}

		go func(conn net.Conn) {
			defer func() { <-ingressSem }()
			handleClientTCP(conn)
		}(c)
	}
}
