package main

import (
	"context"
	"expvar"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/pprof"
	"os"
	"os/signal"
	"strconv"
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
	defaultGoAwayShutdownDrainMs          = 500
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

	tlsCfg, err := tlsutil.GRPCTLSConfig()
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

	serverErrCh := make(chan error, 4)

	go func() {
		if err := admin.Serve(":8443", repo); err != nil && err != http.ErrServerClosed {
			serverErrCh <- fmt.Errorf("admin server: %w", err)
		}
	}()
	go func() {
		if err := grpcserver.Serve(":50051", tlsCfg, repo); err != nil {
			serverErrCh <- fmt.Errorf("grpc server: %w", err)
		}
	}()

	go func() {
		mux := http.NewServeMux()

		mux.Handle("/debug/vars", expvar.Handler())

		mux.HandleFunc("/debug/pprof/", pprof.Index)
		mux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
		mux.HandleFunc("/debug/pprof/profile", pprof.Profile)
		mux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
		mux.HandleFunc("/debug/pprof/trace", pprof.Trace)

		srv := &http.Server{
			Addr:              "127.0.0.1:6060",
			Handler:           mux,
			ReadHeaderTimeout: 5 * time.Second,
		}

		log.Println("debug server (pprof/vars) listening on", srv.Addr)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Println("debug server error:", err)
		}
	}()

	shutdownCtx, stopSignals := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stopSignals()

	go func() {
		if err := ingress.Listen(":443"); err != nil {
			serverErrCh <- fmt.Errorf("ingress listener: %w", err)
		}
	}()

	select {
	case <-shutdownCtx.Done():
		stopSignals()
	case err := <-serverErrCh:
		log.Fatal(err)
	}

	notified := notifyPlannedShutdown()
	log.Printf("planned shutdown: sent GoAway to %d active device(s)", notified)
	time.Sleep(plannedShutdownDrainDuration())
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
