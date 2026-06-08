package tlsutil

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"os"
	"strings"
)

func GRPCTLSConfig(certFile string, keyFile string, clientCAFile string) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("load gRPC certificate: %w", err)
	}

	caPEM, err := os.ReadFile(clientCAFile)
	if err != nil {
		return nil, fmt.Errorf("read device CA certificate: %w", err)
	}

	caPool := x509.NewCertPool()
	if !caPool.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("device CA certificate contains no valid certificates")
	}

	clientAuth := tls.RequireAndVerifyClientCert
	switch strings.ToLower(strings.TrimSpace(os.Getenv("TLS_CLIENT_AUTH"))) {
	case "request":
		clientAuth = tls.RequestClientCert
	case "none":
		clientAuth = tls.NoClientCert
	case "", "require":
		clientAuth = tls.RequireAndVerifyClientCert
	}

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientCAs:    caPool,
		ClientAuth:   clientAuth,
		MinVersion:   tls.VersionTLS12,

		GetConfigForClient: func(info *tls.ClientHelloInfo) (*tls.Config, error) {
			addr := "<nil>"
			if info != nil && info.Conn != nil {
				addr = info.Conn.RemoteAddr().String()
			}
			if info == nil {
				log.Println("TLS ClientHello: nil info")
			} else {
				log.Printf("TLS ClientHello from %s: ServerName=%q, SupportedProtos=%v, CipherSuites=%v",
					addr, info.ServerName, info.SupportedProtos, info.CipherSuites)
			}
			return nil, nil
		},
	}, nil
}
