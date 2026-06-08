package grpcserver

import (
	"context"
	"net"
)

type txtResolver interface {
	LookupTXT(context.Context, string) ([]string, error)
}

type netTXTResolver struct {
	resolver *net.Resolver
}

func (r netTXTResolver) LookupTXT(ctx context.Context, name string) ([]string, error) {
	resolver := r.resolver
	if resolver == nil {
		resolver = net.DefaultResolver
	}
	return resolver.LookupTXT(ctx, name)
}
