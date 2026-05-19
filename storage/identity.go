package storage

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"

	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
)

func ClientCertFingerprint(ctx context.Context) (string, error) {
	p, ok := peer.FromContext(ctx)
	if !ok {
		return "", errors.New("peer info is missing")
	}

	tlsInfo, ok := p.AuthInfo.(credentials.TLSInfo)
	if !ok {
		return "", fmt.Errorf("unexpected auth info type %T", p.AuthInfo)
	}

	if len(tlsInfo.State.PeerCertificates) == 0 {
		return "", errors.New("client certificate is missing")
	}

	sum := sha256.Sum256(tlsInfo.State.PeerCertificates[0].Raw)
	return hex.EncodeToString(sum[:]), nil
}
