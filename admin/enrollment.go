package admin

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"os"
	"strings"
	"time"
)

var EnrollmentToken string

type enrollmentHandler struct {
	caCert *x509.Certificate
	caKey  crypto.Signer
	caPEM  []byte
}

type enrollRequest struct {
	Token      string `json:"token"`
	CSRPEM     string `json:"csr_pem"`
	DeviceName string `json:"device_name"`
}

type enrollResponse struct {
	CertificatePEM string `json:"certificate_pem"`
	CACertificate  string `json:"ca_certificate_pem"`
	Fingerprint    string `json:"fingerprint"`
	ExpiresAt      string `json:"expires_at"`
}

func newEnrollmentHandler(caCertPath string, caKeyPath string) (http.Handler, error) {
	if EnrollmentToken == "" {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "device enrollment is disabled", http.StatusServiceUnavailable)
		}), nil
	}

	caCert, caPEM, err := loadCACertificate(caCertPath)
	if err != nil {
		return nil, err
	}

	caKey, err := loadCAKey(caKeyPath)
	if err != nil {
		return nil, err
	}

	h := &enrollmentHandler{
		caCert: caCert,
		caKey:  caKey,
		caPEM:  caPEM,
	}
	return http.HandlerFunc(h.handle), nil
}

func (h *enrollmentHandler) handle(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req enrollRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64*1024)).Decode(&req); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}

	token := strings.TrimSpace(req.Token)
	if token == "" {
		token = strings.TrimSpace(r.Header.Get("X-Enrollment-Token"))
	}
	if token != EnrollmentToken {
		adminLogger.Printf("ENROLL AUTH_FAIL ip=%s device=%q", r.RemoteAddr, req.DeviceName)
		http.Error(w, "invalid enrollment token", http.StatusForbidden)
		return
	}

	csr, err := parseCSR(req.CSRPEM)
	if err != nil {
		http.Error(w, "invalid csr", http.StatusBadRequest)
		return
	}
	if err := csr.CheckSignature(); err != nil {
		http.Error(w, "invalid csr signature", http.StatusBadRequest)
		return
	}

	der, expiresAt, err := h.signClientCertificate(csr)
	if err != nil {
		adminLogger.Printf("ENROLL SIGN_FAIL ip=%s device=%q err=%v", r.RemoteAddr, req.DeviceName, err)
		http.Error(w, "cannot sign certificate", http.StatusInternalServerError)
		return
	}

	sum := sha256.Sum256(der)
	fingerprint := hex.EncodeToString(sum[:])
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})

	adminLogger.Printf(
		"ENROLL ISSUED fingerprint=%s device=%q subject=%q ip=%s",
		fingerprint,
		req.DeviceName,
		csr.Subject.String(),
		r.RemoteAddr,
	)

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(enrollResponse{
		CertificatePEM: string(certPEM),
		CACertificate:  string(h.caPEM),
		Fingerprint:    fingerprint,
		ExpiresAt:      expiresAt.Format(time.RFC3339),
	}); err != nil {
		adminLogger.Printf("ENROLL WRITE_FAIL fingerprint=%s err=%v", fingerprint, err)
	}
}

func (h *enrollmentHandler) signClientCertificate(csr *x509.CertificateRequest) ([]byte, time.Time, error) {
	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("generate serial: %w", err)
	}

	now := time.Now().UTC()
	expiresAt := now.Add(365 * 24 * time.Hour)
	subject := csr.Subject
	if subject.CommonName == "" {
		subject = pkix.Name{CommonName: "android-device"}
	}

	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               subject,
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              expiresAt,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}

	der, err := x509.CreateCertificate(rand.Reader, template, h.caCert, csr.PublicKey, h.caKey)
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("create certificate: %w", err)
	}

	return der, expiresAt, nil
}

func loadCACertificate(path string) (*x509.Certificate, []byte, error) {
	caPEM, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, fmt.Errorf("read CA certificate: %w", err)
	}

	block, _ := pem.Decode(caPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, nil, errors.New("CA certificate PEM is invalid")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("parse CA certificate: %w", err)
	}
	return cert, caPEM, nil
}

func loadCAKey(path string) (crypto.Signer, error) {
	keyPEM, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read CA key: %w", err)
	}

	block, _ := pem.Decode(keyPEM)
	if block == nil {
		return nil, errors.New("CA key PEM is invalid")
	}

	if key, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		return signerFromKey(key)
	}
	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	if key, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
		return key, nil
	}

	return nil, errors.New("unsupported CA private key format")
}

func signerFromKey(key any) (crypto.Signer, error) {
	switch k := key.(type) {
	case *rsa.PrivateKey:
		return k, nil
	case *ecdsa.PrivateKey:
		return k, nil
	case crypto.Signer:
		return k, nil
	default:
		return nil, fmt.Errorf("unsupported private key type %T", key)
	}
}

func parseCSR(csrPEM string) (*x509.CertificateRequest, error) {
	block, _ := pem.Decode([]byte(csrPEM))
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		return nil, errors.New("CSR PEM is invalid")
	}

	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse CSR: %w", err)
	}
	return csr, nil
}
