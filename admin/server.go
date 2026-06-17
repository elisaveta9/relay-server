package admin

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"relay/storage"
	"time"
)

type Server struct {
	httpServer *http.Server
	certFile   string
	keyFile    string
}

type ServerConfig struct {
	Addr         string
	CertFile     string
	KeyFile      string
	DeviceCAFile string
	DeviceCAKey  string
}

func NewServer(config ServerConfig, repo *storage.Repository) (*Server, error) {
	mux := http.NewServeMux()

	mux.Handle("/domains", requireAPIKey(requireCSRF(http.HandlerFunc(domainsHandler(repo)))))
	ServeAPIv1(mux, repo)

	enrollHandler, err := newEnrollmentHandler(config.DeviceCAFile, config.DeviceCAKey, repo)
	if err != nil {
		return nil, fmt.Errorf("cannot initialize enrollment handler: %w", err)
	}
	mux.Handle("/enroll", enrollHandler)

	mux.HandleFunc("/admin.css", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "admin.css")
	})
	mux.HandleFunc("/admin.js", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "admin.js")
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		http.ServeFile(w, r, "admin.html")
	})

	return &Server{
		httpServer: &http.Server{
			Addr:              config.Addr,
			Handler:           securityHeaders(mux),
			ReadHeaderTimeout: 5 * time.Second,
			ReadTimeout:       15 * time.Second,
			WriteTimeout:      30 * time.Second,
			IdleTimeout:       60 * time.Second,
		},
		certFile: config.CertFile,
		keyFile:  config.KeyFile,
	}, nil
}

func (s *Server) Serve() error {
	log.Println("Admin API listening on", s.httpServer.Addr)
	return s.httpServer.ListenAndServeTLS(s.certFile, s.keyFile)
}

func (s *Server) Shutdown(ctx context.Context) error {
	return s.httpServer.Shutdown(ctx)
}
