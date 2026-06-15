package tlsutil

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"os"
	"strings"
	"time"
)

const fingerprintVerificationTimeout = 3 * time.Second

type DeviceFingerprintVerifier interface {
	VerifyDeviceFingerprint(ctx context.Context, fingerprint string) error
}

func GRPCTLSConfig(
	certFile string,
	keyFile string,
	clientCAFile string,
	verifiers ...DeviceFingerprintVerifier,
) (*tls.Config, error) {
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

	clientAuth, err := clientAuthMode(os.Getenv("TLS_CLIENT_AUTH"))
	if err != nil {
		return nil, err
	}

	var verifier DeviceFingerprintVerifier
	if len(verifiers) > 0 {
		verifier = verifiers[0]
	}
	if verifier == nil {
		return nil, errors.New("device fingerprint verifier is required")
	}

	return &tls.Config{
		Certificates:          []tls.Certificate{cert},
		ClientCAs:             caPool,
		ClientAuth:            clientAuth,
		MinVersion:            tls.VersionTLS12,
		VerifyPeerCertificate: verifyPeerCertificate(caPool, verifier),
		VerifyConnection: func(state tls.ConnectionState) error {
			if len(state.PeerCertificates) == 0 {
				return errors.New("client certificate is required")
			}
			return nil
		},

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

func clientAuthMode(value string) (tls.ClientAuthType, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "request":
		return tls.RequestClientCert, nil
	case "", "require":
		return tls.RequireAndVerifyClientCert, nil
	default:
		return 0, fmt.Errorf("unsupported TLS_CLIENT_AUTH value %q", value)
	}
}

func verifyPeerCertificate(
	clientCAs *x509.CertPool,
	verifier DeviceFingerprintVerifier,
) func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
	return func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
		if len(rawCerts) == 0 {
			return errors.New("client certificate is required")
		}

		certs := make([]*x509.Certificate, 0, len(rawCerts))
		for _, rawCert := range rawCerts {
			cert, err := x509.ParseCertificate(rawCert)
			if err != nil {
				return fmt.Errorf("parse client certificate: %w", err)
			}
			certs = append(certs, cert)
		}

		if len(verifiedChains) == 0 {
			intermediates := x509.NewCertPool()
			for _, cert := range certs[1:] {
				intermediates.AddCert(cert)
			}
			if _, err := certs[0].Verify(x509.VerifyOptions{
				Roots:         clientCAs,
				Intermediates: intermediates,
				KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
			}); err != nil {
				return fmt.Errorf("verify client certificate: %w", err)
			}
		}

		sum := sha256.Sum256(certs[0].Raw)
		fingerprint := hex.EncodeToString(sum[:])
		ctx, cancel := context.WithTimeout(context.Background(), fingerprintVerificationTimeout)
		defer cancel()
		if err := verifier.VerifyDeviceFingerprint(ctx, fingerprint); err != nil {
			return fmt.Errorf("device certificate is not authorized: %w", err)
		}
		return nil
	}
}
