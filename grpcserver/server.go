package grpcserver

import (
	"context"
	"crypto/tls"
	"log"
	"net"
	"relay/storage"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/keepalive"

	controlpb "relay/proto/control/v2"
	tunnelpb "relay/proto/tunnel/v2"
)

const grpcMaxMessageSizeBytes = 8 * 1024 * 1024

type Server struct {
	grpcServer  *grpc.Server
	listener    net.Listener
	repo        *storage.Repository
	cleanupStop chan struct{}
	stopOnce    sync.Once
}

func NewServer(addr string, tlsCfg *tls.Config, repo *storage.Repository) (*Server, error) {
	const (
		maxConcurrentStreams = 1024

		maxConnectionAge = 0 * time.Minute
	)

	grpcServer := grpc.NewServer(
		grpc.Creds(credentials.NewTLS(tlsCfg)),

		grpc.MaxConcurrentStreams(maxConcurrentStreams),

		grpc.MaxRecvMsgSize(grpcMaxMessageSizeBytes),
		grpc.MaxSendMsgSize(grpcMaxMessageSizeBytes),

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
		return nil, err
	}

	return &Server{
		grpcServer:  grpcServer,
		listener:    ln,
		repo:        repo,
		cleanupStop: make(chan struct{}),
	}, nil
}

func (s *Server) Serve() error {
	go cleanupExpiredDomainOwnershipChallenges(s.repo, s.cleanupStop)
	log.Println("gRPC listening on", s.listener.Addr())
	return s.grpcServer.Serve(s.listener)
}

func (s *Server) Shutdown(ctx context.Context) error {
	s.stopOnce.Do(func() {
		close(s.cleanupStop)
	})

	done := make(chan struct{})
	go func() {
		s.grpcServer.GracefulStop()
		close(done)
	}()

	select {
	case <-done:
		return nil
	case <-ctx.Done():
		s.grpcServer.Stop()
		<-done
		return ctx.Err()
	}
}

func cleanupExpiredDomainOwnershipChallenges(repo *storage.Repository, stop <-chan struct{}) {
	interval := time.Duration(envInt("RELAY_DNS_CHALLENGE_CLEANUP_INTERVAL_SECONDS", 60)) * time.Second
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			ctx, cancel := context.WithTimeout(context.Background(), interval)
			deleted, err := repo.DeleteExpiredDomainOwnershipChallenges(ctx)
			cancel()
			if err != nil {
				log.Printf("delete expired DNS challenges failed: %v", err)
			} else if deleted > 0 {
				log.Printf("deleted %d expired DNS challenge(s)", deleted)
			}
		case <-stop:
			return
		}
	}
}
