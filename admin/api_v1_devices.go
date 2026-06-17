package admin

import (
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	tunnelpb "relay/proto/tunnel/v2"
	"relay/registry"
	"relay/storage"
)

type deviceListResponseItem struct {
	ID                 string               `json:"id"`
	Fingerprint        string               `json:"fingerprint"`
	Status             storage.DeviceStatus `json:"status"`
	Connected          bool                 `json:"connected"`
	DomainCount        int64                `json:"domain_count"`
	ActiveSessionCount int                  `json:"active_session_count"`
	LastSeenAt         time.Time            `json:"last_seen_at"`
	CreatedAt          time.Time            `json:"created_at"`
}

type deviceListResponse struct {
	Items      []deviceListResponseItem `json:"items"`
	Page       int                      `json:"page"`
	PerPage    int                      `json:"per_page"`
	Total      int64                    `json:"total"`
	TotalPages int                      `json:"total_pages"`
}

type deviceRevokeResponse struct {
	Fingerprint       string               `json:"fingerprint"`
	Status            storage.DeviceStatus `json:"status"`
	DisconnectedCount int                  `json:"disconnected_count"`
}

func devicesV1Handler(repo *storage.Repository, withAction bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		path := strings.Trim(strings.TrimPrefix(r.URL.Path, "/devices"), "/")

		if !withAction {
			if path != "" {
				http.NotFound(w, r)
				return
			}
			if r.Method != http.MethodGet {
				http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
				return
			}
			handleListDevices(w, r, repo)
			return
		}

		parts := strings.Split(path, "/")
		if len(parts) != 2 || parts[0] == "" || parts[1] != "revoke" {
			http.NotFound(w, r)
			return
		}
		if r.Method != http.MethodPost {
			http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
			return
		}
		handleRevokeDevice(w, r, repo, parts[0])
	}
}

func handleListDevices(w http.ResponseWriter, r *http.Request, repo *storage.Repository) {
	activeFingerprints := activeDeviceFingerprints()
	options, err := deviceListOptionsFromRequest(r, activeFingerprints)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		writeJSONResponse(w, errorResponse{Error: err.Error()})
		return
	}

	page, err := repo.ListDevicesFiltered(r.Context(), options)
	if err != nil {
		http.Error(w, `{"error":"cannot list devices"}`, http.StatusInternalServerError)
		return
	}

	out := make([]deviceListResponseItem, 0, len(page.Devices))
	for _, summary := range page.Devices {
		active := registry.Global.DevicesForFingerprint(summary.CertFingerprint)
		out = append(out, deviceListResponseItem{
			ID:                 summary.ID.String(),
			Fingerprint:        summary.CertFingerprint,
			Status:             summary.Status,
			Connected:          len(active) > 0,
			DomainCount:        summary.DomainCount,
			ActiveSessionCount: len(active),
			LastSeenAt:         summary.LastSeenAt,
			CreatedAt:          summary.CreatedAt,
		})
	}
	totalPages := 0
	if page.Total > 0 {
		totalPages = int((page.Total + int64(page.PerPage) - 1) / int64(page.PerPage))
	}
	writeJSONResponse(w, deviceListResponse{
		Items:      out,
		Page:       page.Page,
		PerPage:    page.PerPage,
		Total:      page.Total,
		TotalPages: totalPages,
	})
}

func deviceListOptionsFromRequest(r *http.Request, connectedFingerprints []string) (storage.DeviceListOptions, error) {
	query := r.URL.Query()
	options := storage.DeviceListOptions{
		Page:                  1,
		PerPage:               50,
		ConnectedFingerprints: connectedFingerprints,
	}

	if raw := strings.TrimSpace(query.Get("page")); raw != "" {
		value, err := strconv.Atoi(raw)
		if err != nil || value < 1 {
			return options, errors.New("page must be a positive integer")
		}
		options.Page = value
	}
	if raw := strings.TrimSpace(query.Get("per_page")); raw != "" {
		value, err := strconv.Atoi(raw)
		if err != nil || value < 1 || value > 200 {
			return options, errors.New("per_page must be between 1 and 200")
		}
		options.PerPage = value
	}
	if raw := strings.TrimSpace(query.Get("status")); raw != "" {
		status := storage.DeviceStatus(raw)
		switch status {
		case storage.DeviceStatusActive, storage.DeviceStatusRevoked:
			options.Status = &status
		default:
			return options, errors.New("invalid status")
		}
	}
	if raw := strings.TrimSpace(query.Get("connected")); raw != "" {
		value, err := strconv.ParseBool(raw)
		if err != nil {
			return options, errors.New("connected must be true or false")
		}
		options.Connected = &value
	}
	if raw := strings.TrimSpace(query.Get("last_seen_from")); raw != "" {
		value, err := parseDomainDateFilter(raw, false)
		if err != nil {
			return options, errors.New("invalid last_seen_from date")
		}
		options.LastSeenFrom = &value
	}
	if raw := strings.TrimSpace(query.Get("last_seen_to")); raw != "" {
		value, err := parseDomainDateFilter(raw, true)
		if err != nil {
			return options, errors.New("invalid last_seen_to date")
		}
		options.LastSeenTo = &value
	}
	return options, nil
}

func activeDeviceFingerprints() []string {
	devices := registry.Global.DevicesSnapshot()
	out := make([]string, 0, len(devices))
	for _, dev := range devices {
		if dev != nil && dev.Fingerprint != "" {
			out = append(out, dev.Fingerprint)
		}
	}
	return out
}

func handleRevokeDevice(w http.ResponseWriter, r *http.Request, repo *storage.Repository, fingerprint string) {
	revoked, err := repo.RevokeDevice(r.Context(), fingerprint)
	switch {
	case errors.Is(err, storage.ErrFingerprintInvalid):
		http.Error(w, `{"error":"invalid fingerprint"}`, http.StatusBadRequest)
		return
	case errors.Is(err, storage.ErrDeviceNotFound):
		http.Error(w, `{"error":"device not found"}`, http.StatusNotFound)
		return
	case err != nil:
		http.Error(w, `{"error":"cannot revoke device"}`, http.StatusInternalServerError)
		return
	}

	active := registry.Global.DevicesForFingerprint(revoked.CertFingerprint)
	for _, dev := range active {
		for _, domain := range registry.Global.UnbindDevice(dev) {
			logAdmin(
				"UNBIND device_revoke domain=%s fingerprint=%s session=%s",
				domain,
				dev.Fingerprint,
				dev.SessionID,
			)
		}
		dev.CloseWithGoAwayDisconnectReason(
			tunnelpb.TunnelErrorCode_TUNNEL_ERROR_CODE_DEVICE_REVOKED,
			"device revoked by administrator",
			false,
			0,
			tunnelpb.DisconnectReason_DISCONNECT_REASON_DEVICE_REVOKED,
			"admin_device_revoke",
		)
		registry.Global.UnregisterDevice(dev)
	}

	logAdmin(
		"ADMIN DEVICE_REVOKE fingerprint=%s disconnected=%d ip=%s",
		revoked.CertFingerprint,
		len(active),
		r.RemoteAddr,
	)
	writeJSONResponse(w, deviceRevokeResponse{
		Fingerprint:       revoked.CertFingerprint,
		Status:            revoked.Status,
		DisconnectedCount: len(active),
	})
}
