package acme

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

func TestClientRunsACMELifecycle(t *testing.T) {
	accountKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate account key: %v", err)
	}

	server := newACMEMockServer(t)
	defer server.Close()

	client := NewClient(server.URL+"/dir", accountKey)
	ctx := context.Background()

	account, err := client.NewAccount(ctx, AccountRequest{
		Contact:              []string{"mailto:admin@example.test"},
		TermsOfServiceAgreed: true,
	})
	if err != nil {
		t.Fatalf("NewAccount returned error: %v", err)
	}
	if account.Status != "valid" {
		t.Fatalf("account status = %q, want valid", account.Status)
	}
	if client.AccountURL() != server.URL+"/acct/1" {
		t.Fatalf("account url = %q", client.AccountURL())
	}

	order, err := client.NewOrder(ctx, []string{" Example.TEST. "})
	if err != nil {
		t.Fatalf("NewOrder returned error: %v", err)
	}
	if order.Location != server.URL+"/order/1" {
		t.Fatalf("order location = %q", order.Location)
	}
	if len(order.Authorizations) != 1 || order.Authorizations[0] != server.URL+"/authz/1" {
		t.Fatalf("unexpected order authorizations: %#v", order.Authorizations)
	}

	authz, err := client.GetAuthorization(ctx, order.Authorizations[0])
	if err != nil {
		t.Fatalf("GetAuthorization returned error: %v", err)
	}
	if authz.Identifier.Value != "example.test" {
		t.Fatalf("authz identifier = %q, want example.test", authz.Identifier.Value)
	}
	challenge := findChallenge(authz.Challenges, "dns-01")
	if challenge == nil {
		t.Fatalf("dns-01 challenge not found: %#v", authz.Challenges)
	}

	txt, err := DNS01TXTValue(challenge.Token, accountKey)
	if err != nil {
		t.Fatalf("DNS01TXTValue returned error: %v", err)
	}
	if txt == "" {
		t.Fatal("DNS01TXTValue returned empty TXT value")
	}

	accepted, err := client.AcceptChallenge(ctx, challenge.URL)
	if err != nil {
		t.Fatalf("AcceptChallenge returned error: %v", err)
	}
	if accepted.Status != "pending" {
		t.Fatalf("challenge status = %q, want pending", accepted.Status)
	}

	csrDER := makeCSR(t, accountKey)
	finalized, err := client.FinalizeOrder(ctx, order.Finalize, csrDER)
	if err != nil {
		t.Fatalf("FinalizeOrder returned error: %v", err)
	}
	if finalized.Status != "valid" || finalized.Certificate != server.URL+"/cert/1" {
		t.Fatalf("unexpected finalized order: %#v", finalized)
	}

	certPEM, err := client.GetCertificate(ctx, finalized.Certificate)
	if err != nil {
		t.Fatalf("GetCertificate returned error: %v", err)
	}
	if !bytes.Contains(certPEM, []byte("BEGIN CERTIFICATE")) {
		t.Fatalf("certificate response does not contain PEM certificate: %q", certPEM)
	}

	server.AssertSeen(t, "/acct/new", "/order/new", "/authz/1", "/challenge/1", "/finalize/1", "/cert/1")
}

func TestClientReturnsACMEProblem(t *testing.T) {
	accountKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate account key: %v", err)
	}

	var baseURL string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/dir":
			writeJSON(t, w, Directory{
				NewNonce:   baseURL + "/nonce",
				NewAccount: baseURL + "/acct/new",
				NewOrder:   baseURL + "/order/new",
			})
		case "/nonce":
			w.Header().Set("Replay-Nonce", "nonce-1")
			w.WriteHeader(http.StatusNoContent)
		case "/acct/new":
			w.Header().Set("Content-Type", contentTypeProblem)
			w.WriteHeader(http.StatusBadRequest)
			writeJSON(t, w, Problem{
				Type:   "urn:ietf:params:acme:error:malformed",
				Detail: "bad account",
			})
		default:
			http.NotFound(w, r)
		}
	}))
	baseURL = server.URL
	defer server.Close()

	client := NewClient(server.URL+"/dir", accountKey)
	_, err = client.NewAccount(context.Background(), AccountRequest{})
	if err == nil {
		t.Fatal("NewAccount expected error")
	}
	if !strings.Contains(err.Error(), "bad account") {
		t.Fatalf("NewAccount error = %q, want ACME problem detail", err)
	}
}

func TestPostAsGetUsesEmptyPayload(t *testing.T) {
	accountKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate account key: %v", err)
	}

	server := newACMEMockServer(t)
	defer server.Close()

	client := NewClient(server.URL+"/dir", accountKey)
	if _, err := client.NewAccount(context.Background(), AccountRequest{}); err != nil {
		t.Fatalf("NewAccount returned error: %v", err)
	}
	if _, err := client.GetOrder(context.Background(), server.URL+"/order/1"); err != nil {
		t.Fatalf("GetOrder returned error: %v", err)
	}

	payload := server.PayloadFor(t, "/order/1")
	if len(payload) != 0 {
		t.Fatalf("post-as-get payload length = %d, want 0: %q", len(payload), payload)
	}
}

type acmeMockServer struct {
	*httptest.Server

	mu       sync.Mutex
	nextID   int
	nonces   map[string]bool
	seen     []string
	payloads map[string][]byte
	account  crypto.PublicKey
}

func newACMEMockServer(t *testing.T) *acmeMockServer {
	t.Helper()

	mock := &acmeMockServer{
		nextID:   1,
		nonces:   make(map[string]bool),
		payloads: make(map[string][]byte),
	}

	var baseURL string
	mock.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/dir":
			writeJSON(t, w, Directory{
				NewNonce:   baseURL + "/nonce",
				NewAccount: baseURL + "/acct/new",
				NewOrder:   baseURL + "/order/new",
			})
		case "/nonce":
			mock.writeNonce(w)
			w.WriteHeader(http.StatusNoContent)
		case "/acct/new":
			got := mock.readJWS(t, r, "", true)
			mock.setAccountPublicKey(t, got.Protected)
			var req AccountRequest
			decodePayload(t, got.Payload, &req)
			if len(req.Contact) == 1 && req.Contact[0] != "mailto:admin@example.test" {
				t.Fatalf("unexpected account contact: %#v", req.Contact)
			}
			mock.writeNonce(w)
			w.Header().Set("Location", baseURL+"/acct/1")
			w.WriteHeader(http.StatusCreated)
			writeJSON(t, w, Account{Status: "valid", Contact: req.Contact})
		case "/order/new":
			got := mock.readJWS(t, r, baseURL+"/acct/1", false)
			var req OrderRequest
			decodePayload(t, got.Payload, &req)
			if len(req.Identifiers) != 1 || req.Identifiers[0].Value != "example.test" {
				t.Fatalf("unexpected identifiers: %#v", req.Identifiers)
			}
			mock.writeNonce(w)
			w.Header().Set("Location", baseURL+"/order/1")
			w.WriteHeader(http.StatusCreated)
			writeJSON(t, w, Order{
				Status:         "pending",
				Identifiers:    req.Identifiers,
				Authorizations: []string{baseURL + "/authz/1"},
				Finalize:       baseURL + "/finalize/1",
			})
		case "/authz/1":
			mock.readJWS(t, r, baseURL+"/acct/1", false)
			mock.writeNonce(w)
			writeJSON(t, w, Authorization{
				Status:     "pending",
				Identifier: Identifier{Type: "dns", Value: "example.test"},
				Challenges: []Challenge{{
					Type:   "dns-01",
					URL:    baseURL + "/challenge/1",
					Status: "pending",
					Token:  "token-value",
				}},
			})
		case "/challenge/1":
			got := mock.readJWS(t, r, baseURL+"/acct/1", false)
			if !bytes.Equal(got.Payload, []byte("{}")) {
				t.Fatalf("challenge payload = %q, want {}", got.Payload)
			}
			mock.writeNonce(w)
			writeJSON(t, w, Challenge{
				Type:   "dns-01",
				URL:    baseURL + "/challenge/1",
				Status: "pending",
				Token:  "token-value",
			})
		case "/finalize/1":
			got := mock.readJWS(t, r, baseURL+"/acct/1", false)
			var req FinalizeRequest
			decodePayload(t, got.Payload, &req)
			csrDER, err := rawURLEncoding.DecodeString(req.CSR)
			if err != nil {
				t.Fatalf("decode csr: %v", err)
			}
			if _, err := x509.ParseCertificateRequest(csrDER); err != nil {
				t.Fatalf("parse csr: %v", err)
			}
			mock.writeNonce(w)
			w.Header().Set("Location", baseURL+"/order/1")
			writeJSON(t, w, Order{
				Status:      "valid",
				Certificate: baseURL + "/cert/1",
			})
		case "/order/1":
			mock.readJWS(t, r, baseURL+"/acct/1", false)
			mock.writeNonce(w)
			w.Header().Set("Location", baseURL+"/order/1")
			writeJSON(t, w, Order{
				Status:      "valid",
				Certificate: baseURL + "/cert/1",
			})
		case "/cert/1":
			mock.readJWS(t, r, baseURL+"/acct/1", false)
			mock.writeNonce(w)
			w.Header().Set("Content-Type", "application/pem-certificate-chain")
			_, _ = io.WriteString(w, "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n")
		default:
			http.NotFound(w, r)
		}
	}))
	baseURL = mock.URL
	return mock
}

func (s *acmeMockServer) writeNonce(w http.ResponseWriter) {
	s.mu.Lock()
	defer s.mu.Unlock()

	nonce := fmt.Sprintf("nonce-%d", s.nextID)
	s.nextID++
	s.nonces[nonce] = true
	w.Header().Set("Replay-Nonce", nonce)
}

type parsedJWS struct {
	Protected jwsProtected
	Payload   []byte
}

func (s *acmeMockServer) readJWS(t *testing.T, r *http.Request, wantKID string, wantJWK bool) parsedJWS {
	t.Helper()

	if r.Method != http.MethodPost {
		t.Fatalf("%s method = %s, want POST", r.URL.Path, r.Method)
	}
	if ct := r.Header.Get("Content-Type"); ct != contentTypeJoseJSON {
		t.Fatalf("%s content-type = %q, want %q", r.URL.Path, ct, contentTypeJoseJSON)
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		t.Fatalf("read jws body: %v", err)
	}

	var req jwsRequest
	if err := json.Unmarshal(body, &req); err != nil {
		t.Fatalf("decode jws: %v", err)
	}

	protectedJSON, err := rawURLEncoding.DecodeString(req.Protected)
	if err != nil {
		t.Fatalf("decode protected: %v", err)
	}
	var protected jwsProtected
	if err := json.Unmarshal(protectedJSON, &protected); err != nil {
		t.Fatalf("decode protected json: %v", err)
	}
	if protected.URL != s.URL+r.URL.Path {
		t.Fatalf("protected url = %q, want %q", protected.URL, s.URL+r.URL.Path)
	}
	if protected.KID != wantKID {
		t.Fatalf("protected kid = %q, want %q", protected.KID, wantKID)
	}
	if (protected.JWK != nil) != wantJWK {
		t.Fatalf("protected jwk presence = %v, want %v", protected.JWK != nil, wantJWK)
	}
	s.consumeNonce(t, protected.Nonce)

	payload, err := rawURLEncoding.DecodeString(req.Payload)
	if err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	signature, err := rawURLEncoding.DecodeString(req.Signature)
	if err != nil {
		t.Fatalf("decode signature: %v", err)
	}

	pub := s.publicKeyFor(t, protected)
	verifyJWS(t, pub, protected.Alg, []byte(req.Protected+"."+req.Payload), signature)

	s.mu.Lock()
	s.seen = append(s.seen, r.URL.Path)
	s.payloads[r.URL.Path] = append([]byte(nil), payload...)
	s.mu.Unlock()

	return parsedJWS{Protected: protected, Payload: payload}
}

func (s *acmeMockServer) publicKeyFor(t *testing.T, protected jwsProtected) crypto.PublicKey {
	t.Helper()

	if protected.JWK != nil {
		return publicKeyFromJWK(t, *protected.JWK)
	}
	if protected.KID != s.URL+"/acct/1" {
		t.Fatalf("unknown kid: %q", protected.KID)
	}
	return s.accountPublicKey(t)
}

func (s *acmeMockServer) accountPublicKey(t *testing.T) crypto.PublicKey {
	t.Helper()

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.account == nil {
		t.Fatal("account public key was not stored")
	}
	return s.account
}

func (s *acmeMockServer) setAccountPublicKey(t *testing.T, protected jwsProtected) {
	t.Helper()

	if protected.JWK == nil {
		t.Fatal("new account request did not include jwk")
	}
	key := publicKeyFromJWK(t, *protected.JWK)

	s.mu.Lock()
	defer s.mu.Unlock()
	s.account = key
}

func (s *acmeMockServer) consumeNonce(t *testing.T, nonce string) {
	t.Helper()

	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.nonces[nonce] {
		t.Fatalf("unknown or reused nonce: %q", nonce)
	}
	delete(s.nonces, nonce)
}

func (s *acmeMockServer) AssertSeen(t *testing.T, paths ...string) {
	t.Helper()

	s.mu.Lock()
	defer s.mu.Unlock()

	for _, want := range paths {
		found := false
		for _, got := range s.seen {
			if got == want {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("path %s was not called; seen=%v", want, s.seen)
		}
	}
}

func (s *acmeMockServer) PayloadFor(t *testing.T, path string) []byte {
	t.Helper()

	s.mu.Lock()
	defer s.mu.Unlock()
	payload, ok := s.payloads[path]
	if !ok {
		t.Fatalf("no payload for %s", path)
	}
	return append([]byte(nil), payload...)
}

func publicKeyFromJWK(t *testing.T, jwk jsonWebKey) crypto.PublicKey {
	t.Helper()

	switch jwk.KTY {
	case "EC":
		xBytes, err := rawURLEncoding.DecodeString(jwk.X)
		if err != nil {
			t.Fatalf("decode jwk x: %v", err)
		}
		yBytes, err := rawURLEncoding.DecodeString(jwk.Y)
		if err != nil {
			t.Fatalf("decode jwk y: %v", err)
		}
		var curve elliptic.Curve
		switch jwk.Crv {
		case "P-256":
			curve = elliptic.P256()
		case "P-384":
			curve = elliptic.P384()
		default:
			t.Fatalf("unsupported jwk curve: %q", jwk.Crv)
		}
		return &ecdsa.PublicKey{Curve: curve, X: new(big.Int).SetBytes(xBytes), Y: new(big.Int).SetBytes(yBytes)}
	case "RSA":
		nBytes, err := rawURLEncoding.DecodeString(jwk.N)
		if err != nil {
			t.Fatalf("decode jwk n: %v", err)
		}
		eBytes, err := rawURLEncoding.DecodeString(jwk.E)
		if err != nil {
			t.Fatalf("decode jwk e: %v", err)
		}
		return &rsa.PublicKey{N: new(big.Int).SetBytes(nBytes), E: int(new(big.Int).SetBytes(eBytes).Int64())}
	default:
		t.Fatalf("unsupported jwk type: %q", jwk.KTY)
	}
	return nil
}

func verifyJWS(t *testing.T, pub crypto.PublicKey, alg string, signingInput []byte, signature []byte) {
	t.Helper()

	switch alg {
	case "ES256":
		sum := sha256.Sum256(signingInput)
		verifyECDSA(t, pub, sum[:], signature, 32)
	case "ES384":
		sum := sha512.Sum384(signingInput)
		verifyECDSA(t, pub, sum[:], signature, 48)
	case "RS256":
		sum := sha256.Sum256(signingInput)
		rsaKey, ok := pub.(*rsa.PublicKey)
		if !ok {
			t.Fatalf("RS256 public key type = %T", pub)
		}
		if err := rsa.VerifyPKCS1v15(rsaKey, crypto.SHA256, sum[:], signature); err != nil {
			t.Fatalf("verify rsa signature: %v", err)
		}
	default:
		t.Fatalf("unsupported alg: %q", alg)
	}
}

func verifyECDSA(t *testing.T, pub crypto.PublicKey, digest []byte, signature []byte, size int) {
	t.Helper()

	key, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("ecdsa public key type = %T", pub)
	}
	if len(signature) != size*2 {
		t.Fatalf("ecdsa signature length = %d, want %d", len(signature), size*2)
	}
	r := new(big.Int).SetBytes(signature[:size])
	s := new(big.Int).SetBytes(signature[size:])
	if !ecdsa.Verify(key, digest, r, s) {
		t.Fatal("ecdsa signature verification failed")
	}
}

func decodePayload(t *testing.T, payload []byte, out any) {
	t.Helper()

	if err := json.Unmarshal(payload, out); err != nil {
		t.Fatalf("decode payload: %v", err)
	}
}

func writeJSON(t *testing.T, w http.ResponseWriter, value any) {
	t.Helper()

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(value); err != nil {
		t.Fatalf("write json: %v", err)
	}
}

func findChallenge(challenges []Challenge, typ string) *Challenge {
	for i := range challenges {
		if challenges[i].Type == typ {
			return &challenges[i]
		}
	}
	return nil
}

func makeCSR(t *testing.T, key crypto.Signer) []byte {
	t.Helper()

	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: "example.test"},
		DNSNames: []string{"example.test"},
	}, key)
	if err != nil {
		t.Fatalf("create csr: %v", err)
	}
	return csrDER
}
