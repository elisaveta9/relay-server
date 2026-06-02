package acme

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
)

var rawURLEncoding = base64.RawURLEncoding

var errUnsupportedJWK = errors.New("unsupported jwk type")

type jsonWebKey struct {
	KTY string `json:"kty"`
	N   string `json:"n,omitempty"`
	E   string `json:"e,omitempty"`
	Crv string `json:"crv,omitempty"`
	X   string `json:"x,omitempty"`
	Y   string `json:"y,omitempty"`
}

type jwsRequest struct {
	Protected string `json:"protected"`
	Payload   string `json:"payload"`
	Signature string `json:"signature"`
}

type jwsProtected struct {
	Alg   string      `json:"alg"`
	Nonce string      `json:"nonce"`
	URL   string      `json:"url"`
	JWK   *jsonWebKey `json:"jwk,omitempty"`
	KID   string      `json:"kid,omitempty"`
}

func makeJWS(key crypto.Signer, kid string, nonce string, url string, payload []byte) ([]byte, error) {
	if key == nil {
		return nil, errors.New("account key is nil")
	}
	if nonce == "" {
		return nil, errors.New("nonce is empty")
	}
	if url == "" {
		return nil, errors.New("url is empty")
	}

	alg, hash, err := signerAlgorithm(key)
	if err != nil {
		return nil, err
	}

	protected := jwsProtected{
		Alg:   alg,
		Nonce: nonce,
		URL:   url,
	}
	if kid == "" {
		jwk, err := publicJWK(key.Public())
		if err != nil {
			return nil, err
		}
		protected.JWK = &jwk
	} else {
		protected.KID = kid
	}

	protectedJSON, err := json.Marshal(protected)
	if err != nil {
		return nil, fmt.Errorf("marshal protected header: %w", err)
	}

	protected64 := rawURLEncoding.EncodeToString(protectedJSON)
	payload64 := rawURLEncoding.EncodeToString(payload)
	signingInput := protected64 + "." + payload64

	digest, opts, err := digestForSignature(hash, []byte(signingInput))
	if err != nil {
		return nil, err
	}

	sig, err := key.Sign(rand.Reader, digest, opts)
	if err != nil {
		return nil, fmt.Errorf("sign jws: %w", err)
	}

	if ecdsaKey, ok := key.Public().(*ecdsa.PublicKey); ok {
		sig, err = normalizeECDSASignature(ecdsaKey, sig)
		if err != nil {
			return nil, err
		}
	}

	out, err := json.Marshal(jwsRequest{
		Protected: protected64,
		Payload:   payload64,
		Signature: rawURLEncoding.EncodeToString(sig),
	})
	if err != nil {
		return nil, fmt.Errorf("marshal jws: %w", err)
	}
	return out, nil
}

func digestForSignature(hash crypto.Hash, input []byte) ([]byte, crypto.SignerOpts, error) {
	switch hash {
	case crypto.SHA256:
		sum := sha256.Sum256(input)
		return sum[:], hash, nil
	case crypto.SHA384:
		sum := sha512.Sum384(input)
		return sum[:], hash, nil
	case crypto.SHA512:
		sum := sha512.Sum512(input)
		return sum[:], hash, nil
	default:
		return nil, nil, fmt.Errorf("unsupported hash: %v", hash)
	}
}

func signerAlgorithm(key crypto.Signer) (string, crypto.Hash, error) {
	switch pub := key.Public().(type) {
	case *rsa.PublicKey:
		return "RS256", crypto.SHA256, nil
	case *ecdsa.PublicKey:
		switch pub.Curve {
		case elliptic.P256():
			return "ES256", crypto.SHA256, nil
		case elliptic.P384():
			return "ES384", crypto.SHA384, nil
		default:
			return "", 0, errors.New("unsupported ecdsa curve")
		}
	default:
		return "", 0, errors.New("unsupported account key type")
	}
}

func publicJWK(pub crypto.PublicKey) (jsonWebKey, error) {
	switch key := pub.(type) {
	case *rsa.PublicKey:
		return jsonWebKey{
			KTY: "RSA",
			N:   rawURLEncoding.EncodeToString(key.N.Bytes()),
			E:   rawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes()),
		}, nil
	case *ecdsa.PublicKey:
		crv, size, err := jwkCurve(key.Curve)
		if err != nil {
			return jsonWebKey{}, err
		}
		return jsonWebKey{
			KTY: "EC",
			Crv: crv,
			X:   rawURLEncoding.EncodeToString(fixedBytes(key.X, size)),
			Y:   rawURLEncoding.EncodeToString(fixedBytes(key.Y, size)),
		}, nil
	default:
		return jsonWebKey{}, errors.New("unsupported public key type")
	}
}

func jwkCurve(curve elliptic.Curve) (string, int, error) {
	switch curve {
	case elliptic.P256():
		return "P-256", 32, nil
	case elliptic.P384():
		return "P-384", 48, nil
	default:
		return "", 0, errors.New("unsupported ecdsa curve")
	}
}

func fixedBytes(v *big.Int, size int) []byte {
	out := make([]byte, size)
	b := v.Bytes()
	copy(out[size-len(b):], b)
	return out
}

func normalizeECDSASignature(pub *ecdsa.PublicKey, der []byte) ([]byte, error) {
	var pair struct {
		R *big.Int
		S *big.Int
	}
	if _, err := asn1.Unmarshal(der, &pair); err != nil {
		return nil, fmt.Errorf("decode ecdsa signature: %w", err)
	}

	_, size, err := jwkCurve(pub.Curve)
	if err != nil {
		return nil, err
	}

	out := make([]byte, 0, size*2)
	out = append(out, fixedBytes(pair.R, size)...)
	out = append(out, fixedBytes(pair.S, size)...)
	return out, nil
}
