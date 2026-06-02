package acme

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"strings"
	"testing"
)

func TestDNS01Helpers(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate account key: %v", err)
	}

	name := DNS01RecordName(" Example.TEST. ")
	if name != "_acme-challenge.example.test" {
		t.Fatalf("DNS01RecordName = %q", name)
	}

	thumbprint, err := JWKThumbprint(key)
	if err != nil {
		t.Fatalf("JWKThumbprint returned error: %v", err)
	}
	if strings.Contains(thumbprint, "=") {
		t.Fatalf("thumbprint must be unpadded base64url: %q", thumbprint)
	}

	keyAuth, err := KeyAuthorization(" token-value ", key)
	if err != nil {
		t.Fatalf("KeyAuthorization returned error: %v", err)
	}
	if keyAuth != "token-value."+thumbprint {
		t.Fatalf("KeyAuthorization = %q, want token-value.<thumbprint>", keyAuth)
	}

	sum := sha256.Sum256([]byte(keyAuth))
	wantTXT := rawURLEncoding.EncodeToString(sum[:])
	gotTXT, err := DNS01TXTValue(" token-value ", key)
	if err != nil {
		t.Fatalf("DNS01TXTValue returned error: %v", err)
	}
	if gotTXT != wantTXT {
		t.Fatalf("DNS01TXTValue = %q, want %q", gotTXT, wantTXT)
	}
}
