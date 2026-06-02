package acme

import (
	"crypto"
	"crypto/sha256"
	"strings"
)

func KeyAuthorization(token string, accountKey crypto.Signer) (string, error) {
	thumbprint, err := JWKThumbprint(accountKey)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(token) + "." + thumbprint, nil
}

func DNS01RecordName(domain string) string {
	domain = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(domain)), ".")
	if domain == "" {
		return "_acme-challenge"
	}
	return "_acme-challenge." + domain
}

func DNS01TXTValue(token string, accountKey crypto.Signer) (string, error) {
	keyAuth, err := KeyAuthorization(token, accountKey)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256([]byte(keyAuth))
	return rawURLEncoding.EncodeToString(sum[:]), nil
}

func JWKThumbprint(accountKey crypto.Signer) (string, error) {
	jwk, err := publicJWK(accountKey.Public())
	if err != nil {
		return "", err
	}

	canonical, err := canonicalJWK(jwk)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(canonical)
	return rawURLEncoding.EncodeToString(sum[:]), nil
}

func canonicalJWK(jwk jsonWebKey) ([]byte, error) {
	switch jwk.KTY {
	case "RSA":
		return []byte(`{"e":"` + jwk.E + `","kty":"RSA","n":"` + jwk.N + `"}`), nil
	case "EC":
		return []byte(`{"crv":"` + jwk.Crv + `","kty":"EC","x":"` + jwk.X + `","y":"` + jwk.Y + `"}`), nil
	default:
		return nil, errUnsupportedJWK
	}
}
