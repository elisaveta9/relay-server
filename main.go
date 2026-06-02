package main

import (
	"context"
	"expvar"
	"io"
	"log"
	"net/http"
	"net/http/pprof"
	"os"
	"time"

	"relay/admin"
	"relay/grpcserver"
	"relay/ingress"
	"relay/logfile"
	"relay/storage"
	"relay/tlsutil"
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

	admin.InitLogger()

	lf, err := logfile.NewRotatingWriter("server.log", logfile.DefaultMaxBytes, logfile.DefaultMaxBackups)
	if err != nil {
		log.Printf("warning: cannot open server.log: %v", err)
	} else {
		mw := io.MultiWriter(os.Stderr, lf)
		log.SetOutput(mw)
	}

	go admin.Serve(":8443", repo)
	go grpcserver.Serve(":50051", tlsCfg, repo)

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

	ingress.Listen(":443")
}
