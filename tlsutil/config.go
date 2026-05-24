package tlsutil

import (
	"crypto/tls"
	"crypto/x509"
	"io/ioutil"
	"log"
	"os"
	"strings"
)

func GRPCTLSConfig() (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair("certs/server.crt", "certs/server.key")
	if err != nil {
		return nil, err
	}

	caPEM, err := ioutil.ReadFile("certs/ca.crt")
	if err != nil {
		return nil, err
	}

	caPool := x509.NewCertPool()
	caPool.AppendCertsFromPEM(caPEM)

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
