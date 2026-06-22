package main

import (
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"sync"
	"syscall"
	"time"

	"relay/admin"
	"relay/grpcserver"
	"relay/ingress"
	"relay/logfile"
	tunnelpb "relay/proto/tunnel/v2"
	"relay/registry"
	"relay/storage"
	"relay/tlsutil"
)

const (
	defaultGoAwayPlannedRetryAfterSeconds = 5
	defaultGoAwayShutdownDrainMs          = 5000
	defaultShutdownTimeoutSeconds         = 15
)

func main() {
	admin.ApiKey = os.Getenv("SECRET_API_KEY")
	if admin.ApiKey == "" {
		log.Fatal("SECRET_API_KEY is not set")
	}
	admin.EnrollmentToken = os.Getenv("RELAY_ENROLLMENT_TOKEN")
	if admin.EnrollmentToken == "" {
		log.Println("RELAY_ENROLLMENT_TOKEN is not set; device enrollment endpoint is disabled")
	}

	dbDSN := os.Getenv("DATABASE_URL")
	if dbDSN == "" {
		dbDSN = os.Getenv("RELAY_DATABASE_DSN")
	}
	if dbDSN == "" {
		log.Fatal("DATABASE_URL or RELAY_DATABASE_DSN is not set")
	}

	db, err := storage.OpenPostgres(dbDSN)
	if err != nil {
		log.Fatal(err)
	}
	if err := storage.AutoMigrate(context.Background(), db); err != nil {
		log.Fatal(err)
	}
	repo := storage.NewRepository(db)

	tlsCfg, err := tlsutil.GRPCTLSConfig(
		envFile("RELAY_GRPC_CERT_FILE", "certs/server.crt"),
		envFile("RELAY_GRPC_KEY_FILE", "certs/server.key"),
		envFile("RELAY_DEVICE_CA_CERT_FILE", "certs/ca.crt"),
		repo,
	)
	if err != nil {
		log.Fatal(err)
	}

	if err := admin.InitLogger(); err != nil {
		log.Fatal(err)
	}

	lf, err := logfile.NewRotatingWriter("server.log", logfile.DefaultMaxBytes, logfile.DefaultMaxBackups)
	if err != nil {
		log.Printf("warning: cannot open server.log: %v", err)
	} else {
		mw := io.MultiWriter(os.Stderr, lf)
		log.SetOutput(mw)
	}

	serverErrCh := make(chan error, 3)

	adminServer, err := admin.NewServer(admin.ServerConfig{
		Addr:         envFile("RELAY_ADMIN_ADDR", ":8443"),
		CertFile:     envFile("RELAY_ADMIN_CERT_FILE", "certs/admin.crt"),
		KeyFile:      envFile("RELAY_ADMIN_KEY_FILE", "certs/admin.key"),
		DeviceCAFile: envFile("RELAY_DEVICE_CA_CERT_FILE", "certs/ca.crt"),
		DeviceCAKey:  envFile("RELAY_DEVICE_CA_KEY_FILE", "certs/ca.key"),
	}, repo)
	if err != nil {
		log.Fatal(err)
	}
	grpcServer, err := grpcserver.NewServer(envFile("RELAY_GRPC_ADDR", ":50051"), tlsCfg, repo)
	if err != nil {
		log.Fatal(err)
	}
	ingressServer, err := ingress.NewServer(envFile("RELAY_INGRESS_ADDR", ":443"))
	if err != nil {
		log.Fatal(err)
	}

	go func() {
		if err := adminServer.Serve(); err != nil && err != http.ErrServerClosed {
			serverErrCh <- fmt.Errorf("admin server: %w", err)
		}
	}()
	go func() {
		if err := grpcServer.Serve(); err != nil {
			serverErrCh <- fmt.Errorf("grpc server: %w", err)
		}
	}()

	shutdownCtx, stopSignals := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stopSignals()

	go func() {
		if err := ingressServer.Serve(); err != nil {
			serverErrCh <- fmt.Errorf("ingress listener: %w", err)
		}
	}()

	var shutdownReason string
	select {
	case <-shutdownCtx.Done():
		shutdownReason = shutdownCtx.Err().Error()
		stopSignals()
	case err := <-serverErrCh:
		shutdownReason = err.Error()
		log.Printf("server shutdown requested: %v", err)
	}

	if err := ingressServer.StopAccepting(); err != nil {
		log.Printf("stop accepting ingress connections failed: %v", err)
	}
	notified := notifyPlannedShutdown()
	log.Printf("shutdown started: reason=%s sent GoAway to %d active device(s)", shutdownReason, notified)
	time.Sleep(plannedShutdownDrainDuration())

	shutdownCtx, cancelShutdown := context.WithTimeout(
		context.Background(),
		time.Duration(envPositiveInt("RELAY_SHUTDOWN_TIMEOUT_SECONDS", defaultShutdownTimeoutSeconds))*time.Second,
	)
	defer cancelShutdown()
	shutdownServers(shutdownCtx, adminServer, grpcServer, ingressServer)
}

func shutdownServers(
	ctx context.Context,
	adminServer *admin.Server,
	grpcServer *grpcserver.Server,
	ingressServer *ingress.Server,
) {
	var wg sync.WaitGroup
	shutdown := func(name string, fn func(context.Context) error) {
		defer wg.Done()
		if err := fn(ctx); err != nil {
			log.Printf("%s shutdown failed: %v", name, err)
		}
	}

	wg.Add(3)
	go shutdown("admin server", adminServer.Shutdown)
	go shutdown("gRPC server", grpcServer.Shutdown)
	go shutdown("ingress server", ingressServer.Shutdown)
	wg.Wait()
}

func notifyPlannedShutdown() int {
	devices := registry.Global.DevicesSnapshot()
	retryAfterSeconds := uint32(envPositiveInt("RELAY_GOAWAY_PLANNED_RETRY_AFTER_SECONDS", defaultGoAwayPlannedRetryAfterSeconds))
	for _, dev := range devices {
		dev.CloseWithGoAwayDisconnectReason(
			tunnelpb.TunnelErrorCode_TUNNEL_ERROR_CODE_UNSPECIFIED,
			"server shutting down",
			true,
			retryAfterSeconds,
			tunnelpb.DisconnectReason_DISCONNECT_REASON_SERVER_RESTART,
			"server_planned_shutdown",
		)
	}
	return len(devices)
}

func plannedShutdownDrainDuration() time.Duration {
	return time.Duration(envPositiveInt("RELAY_GOAWAY_SHUTDOWN_DRAIN_MS", defaultGoAwayShutdownDrainMs)) * time.Millisecond
}

func envPositiveInt(key string, def int) int {
	if value := os.Getenv(key); value != "" {
		parsed, err := strconv.Atoi(value)
		if err != nil || parsed <= 0 {
			log.Printf("invalid %s=%q, using default=%d", key, value, def)
			return def
		}
		return parsed
	}
	return def
}

func envFile(key string, def string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return def
}
