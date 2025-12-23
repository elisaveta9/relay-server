package ingress

import (
	"log"
	"net"
)

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
		go handleClientTCP(c)
	}
}
