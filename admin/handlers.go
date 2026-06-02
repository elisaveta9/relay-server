package admin

import (
	"context"
	"errors"
	"log"
	"net/http"
	"strings"
	"time"

	tunnelpb "relay/proto/tunnel"
	"relay/registry"
	"relay/storage"
)

func domainsHandler(repo *storage.Repository) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {

		case "GET":
			domains, err := repo.ListDomains(r.Context())
			if err != nil {
				http.Error(w, "cannot list domains", http.StatusInternalServerError)
				return
			}
			for _, domain := range domains {
				w.Write([]byte(domain.FQDN + "\n"))
			}

		case "POST":
			domain := strings.ToLower(r.URL.Query().Get("domain"))
			if domain == "" {
				http.Error(w, "domain required", http.StatusBadRequest)
				return
			}

			fingerprint := ownerFingerprint(r)
			if fingerprint == "" {
				http.Error(w, "cert_fingerprint required", http.StatusBadRequest)
				return
			}

			created, err := repo.RegisterDomainForFingerprint(r.Context(), fingerprint, domain)
			if err != nil {
				writeStorageHTTPError(w, err)
				return
			}
			adminLogger.Printf(
				"ADMIN ADD domain=%s owner=%s ip=%s",
				created.FQDN, fingerprint, r.RemoteAddr,
			)
			w.Write([]byte("registered\n"))

		case "DELETE":
			domain := strings.ToLower(r.URL.Query().Get("domain"))

			deleted, existed, err := repo.DeleteDomain(r.Context(), domain)
			if err != nil {
				writeStorageHTTPError(w, err)
				return
			}

			if existed && deleted != nil {
				notifyUnboundDevice(deleted.FQDN)
				adminLogger.Printf(
					"ADMIN DELETE domain=%s ip=%s",
					deleted.FQDN, r.RemoteAddr,
				)
			}

			w.Write([]byte("deleted\n"))

		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	}
}

func ownerFingerprint(r *http.Request) string {
	for _, key := range []string{"cert_fingerprint", "fingerprint", "device_fingerprint"} {
		if value := strings.TrimSpace(r.URL.Query().Get(key)); value != "" {
			return value
		}
	}
	return strings.TrimSpace(r.Header.Get("X-Device-Fingerprint"))
}

func notifyUnboundDevice(domain string) {
	dev, existed := registry.Global.Unbind(domain)
	if existed && dev != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
		defer cancel()

		if err := dev.SendFrame(ctx, &tunnelpb.Frame{
			Type:    tunnelpb.FrameType_FRAME_BIND_REJECTED,
			Payload: []byte(domain),
		}); err != nil {
			log.Printf("send BIND_REJECTED after admin unbind failed: domain=%s fingerprint=%s session=%s err=%v", domain, dev.Fingerprint, dev.SessionID, err)
		}
	}
}

func writeStorageHTTPError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, storage.ErrFingerprintInvalid):
		http.Error(w, "invalid cert_fingerprint", http.StatusBadRequest)
	case errors.Is(err, storage.ErrDomainInvalid):
		http.Error(w, "invalid domain", http.StatusBadRequest)
	case errors.Is(err, storage.ErrDomainAlreadyUsed):
		http.Error(w, "domain already registered to another device", http.StatusConflict)
	case errors.Is(err, storage.ErrDeviceRevoked):
		http.Error(w, "device is revoked", http.StatusForbidden)
	default:
		http.Error(w, "storage error", http.StatusInternalServerError)
	}
}
