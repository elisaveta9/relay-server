package admin

import (
	"context"
	"errors"
	"log"
	"net/http"
	"strings"
	"time"

	"relay/device"
	tunnelpb "relay/proto/tunnel/v2"
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
				if _, err := w.Write([]byte(domain.FQDN + "\n")); err != nil {
					log.Printf("write domain list response failed: domain=%s err=%v", domain.FQDN, err)
					return
				}
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
			if _, err := w.Write([]byte("registered\n")); err != nil {
				log.Printf("write register response failed: domain=%s err=%v", created.FQDN, err)
			}

		case "DELETE":
			domain := strings.ToLower(r.URL.Query().Get("domain"))

			deleted, existed, err := repo.DeleteDomain(r.Context(), domain)
			if err != nil {
				writeStorageHTTPError(w, err)
				return
			}

			if existed && deleted != nil {
				notifyUnboundDevice(repo, deleted.FQDN, "domain deleted")
				adminLogger.Printf(
					"ADMIN DELETE domain=%s ip=%s",
					deleted.FQDN, r.RemoteAddr,
				)
			}

			if _, err := w.Write([]byte("deleted\n")); err != nil {
				log.Printf("write delete response failed: domain=%s err=%v", domain, err)
			}

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

func notifyUnboundDevice(repo *storage.Repository, domain string, reason string) {
	dev, existed := registry.Global.Unbind(domain)
	if existed && dev != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
		defer cancel()

		if err := dev.SendFrame(ctx, tunnelpb.NewDomainRevokedFrameWithReason(domain, reason, tunnelpb.DomainRevokeReason_DOMAIN_REVOKE_REASON_ADMIN_ACTION)); err != nil {
			log.Printf("send domain revoked after admin unbind failed: domain=%s fingerprint=%s session=%s err=%v", domain, dev.Fingerprint, dev.SessionID, err)
		}
		sendDomainSync(ctx, repo, dev)
	}
}

func sendDomainSync(ctx context.Context, repo *storage.Repository, dev *device.Device) {
	domains, err := repo.ListDomainsForFingerprint(ctx, dev.Fingerprint)
	if err != nil {
		log.Printf("load domains for DomainSync failed: fingerprint=%s session=%s err=%v", dev.Fingerprint, dev.SessionID, err)
		return
	}
	if err := dev.SendFrame(ctx, tunnelpb.NewDomainSyncFrame(domainBindings(domains, dev))); err != nil {
		log.Printf("send DomainSync failed: fingerprint=%s session=%s err=%v", dev.Fingerprint, dev.SessionID, err)
	}
}

func domainBindings(domains []storage.Domain, target *device.Device) []*tunnelpb.DomainBinding {
	out := make([]*tunnelpb.DomainBinding, 0, len(domains))
	for _, domain := range domains {
		active, exists := registry.Global.Get(domain.FQDN)
		bound := target != nil && exists && active == target
		out = append(out, &tunnelpb.DomainBinding{
			Domain: domain.FQDN,
			Status: domainStatus(domain.Status),
			Bound:  bound,
		})
	}
	return out
}

func domainStatus(status storage.DomainStatus) tunnelpb.DomainStatus {
	switch status {
	case storage.DomainStatusRegistered, storage.DomainStatusBound:
		return tunnelpb.DomainStatus_DOMAIN_STATUS_REGISTERED
	case storage.DomainStatusDisabled:
		return tunnelpb.DomainStatus_DOMAIN_STATUS_DISABLED
	default:
		return tunnelpb.DomainStatus_DOMAIN_STATUS_UNSPECIFIED
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
