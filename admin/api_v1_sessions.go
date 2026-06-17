package admin

import (
	"net/http"
	"time"

	"relay/registry"
	"relay/storage"
)

type sessionListResponseItem struct {
	ID          string     `json:"id"`
	DeviceID    string     `json:"device_id"`
	Fingerprint string     `json:"fingerprint"`
	Active      bool       `json:"active"`
	OpenedAt    time.Time  `json:"opened_at"`
	ClosedAt    *time.Time `json:"closed_at,omitempty"`
}

func sessionsV1Handler(repo *storage.Repository) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		if r.URL.Path != "/sessions" {
			http.NotFound(w, r)
			return
		}
		if r.Method != http.MethodGet {
			http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
			return
		}

		fingerprint := r.URL.Query().Get("fingerprint")
		var sessions []storage.DeviceSession
		var err error
		if fingerprint == "" {
			sessions, err = repo.ListOpenDeviceSessions(r.Context())
		} else {
			sessions, err = repo.ListDeviceSessionsForFingerprint(r.Context(), fingerprint)
		}
		if err != nil {
			if fingerprint != "" {
				writeStorageHTTPErrorJSON(w, err)
				return
			}
			http.Error(w, `{"error":"cannot list sessions"}`, http.StatusInternalServerError)
			return
		}

		connectedSessionIDs := make(map[string]struct{})
		for _, dev := range registry.Global.DevicesSnapshot() {
			if dev != nil {
				connectedSessionIDs[dev.SessionID] = struct{}{}
			}
		}

		out := make([]sessionListResponseItem, 0, len(sessions))
		for _, session := range sessions {
			_, connected := connectedSessionIDs[session.ID.String()]
			if fingerprint == "" && !connected {
				continue
			}
			out = append(out, sessionListResponseItem{
				ID:          session.ID.String(),
				DeviceID:    session.DeviceID.String(),
				Fingerprint: session.Device.CertFingerprint,
				Active:      connected,
				OpenedAt:    session.OpenedAt,
				ClosedAt:    session.ClosedAt,
			})
		}
		writeJSONResponse(w, out)
	}
}
