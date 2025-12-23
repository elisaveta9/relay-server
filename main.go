package main

import (
	"log"
	"os"

	"relay/admin"
	"relay/grpcserver"
	"relay/ingress"
	"relay/tlsutil"
)

func main() {
	admin.ApiKey = os.Getenv("SECRET_API_KEY")
	if admin.ApiKey == "" {
		log.Fatal("SECRET_API_KEY is not set")
	}

	tlsCfg, err := tlsutil.GRPCTLSConfig()
	if err != nil {
		log.Fatal(err)
	}

	admin.InitLogger()

	go admin.Serve(":8443")
	go grpcserver.Serve(":50051", tlsCfg)

	ingress.Listen(":443")
}
