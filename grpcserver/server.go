package grpcserver

import (
	"crypto/tls"
	"log"
	"net"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/keepalive"

	controlpb "relay/proto/control"
	tunnelpb "relay/proto/tunnel"
)

func Serve(addr string, tlsCfg *tls.Config) {
	grpcServer := grpc.NewServer(
		grpc.Creds(credentials.NewTLS(tlsCfg)),
		grpc.KeepaliveParams(keepalive.ServerParameters{
			Time:    30 * time.Second,
			Timeout: 10 * time.Second,
		}),
	)

	tunnelpb.RegisterTunnelServiceServer(grpcServer, &TunnelServiceImpl{})
	controlpb.RegisterControlServiceServer(grpcServer, &ControlServiceImpl{})

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatal(err)
	}

	log.Println("gRPC listening on", addr)
	log.Fatal(grpcServer.Serve(ln))
}
