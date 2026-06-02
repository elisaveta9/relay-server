package grpcserver

import (
	"crypto/tls"
	"log"
	"net"
	"relay/storage"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/keepalive"

	controlpb "relay/proto/control"
	tunnelpb "relay/proto/tunnel"
)

func Serve(addr string, tlsCfg *tls.Config, repo *storage.Repository) {
	const (
		maxConcurrentStreams = 1024
		maxRecvMsgSize       = 8 * 1024 * 1024
		maxSendMsgSize       = 8 * 1024 * 1024

		maxConnectionAge = 0 * time.Minute
	)

	grpcServer := grpc.NewServer(
		grpc.Creds(credentials.NewTLS(tlsCfg)),

		grpc.MaxConcurrentStreams(maxConcurrentStreams),

		grpc.MaxRecvMsgSize(maxRecvMsgSize),
		grpc.MaxSendMsgSize(maxSendMsgSize),

		grpc.KeepaliveParams(keepalive.ServerParameters{
			Time:                  30 * time.Second,
			Timeout:               10 * time.Second,
			MaxConnectionAge:      maxConnectionAge,
			MaxConnectionAgeGrace: 5 * time.Second,
		}),

		grpc.KeepaliveEnforcementPolicy(keepalive.EnforcementPolicy{
			MinTime:             10 * time.Second,
			PermitWithoutStream: true,
		}),
	)

	tunnelpb.RegisterTunnelServiceServer(grpcServer, &TunnelServiceImpl{Store: repo})
	controlpb.RegisterControlServiceServer(grpcServer, &ControlServiceImpl{Store: repo})

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatal(err)
	}

	log.Println("gRPC listening on", addr)
	log.Fatal(grpcServer.Serve(ln))
}
