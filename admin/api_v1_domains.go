package admin

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"

	"relay/storage"
)

type domainListResponseItem struct {
	ID        string               `json:"id"`
	FQDN      string               `json:"fqdn"`
	Status    storage.DomainStatus `json:"status"`
	DeviceID  string               `json:"device_id"`
	CreatedAt time.Time            `json:"created_at"`
}

type domainCreateRequest struct {
	FQDN              string `json:"fqdn"`
	DeviceFingerprint string `json:"device_fingerprint"`
}

type domainCreateResponse struct {
	ID        string               `json:"id"`
	FQDN      string               `json:"fqdn"`
	Status    storage.DomainStatus `json:"status"`
	DeviceID  string               `json:"device_id"`
	CreatedAt time.Time            `json:"created_at"`
}

type domainPatchRequest struct {
	Status storage.DomainStatus `json:"status"`
}

type errorResponse struct {
	Error string `json:"error"`
}

func domainsV1Handler(repo *storage.Repository, withID bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")

		path := strings.TrimPrefix(r.URL.Path, "/domains")
		path = strings.TrimPrefix(path, "/") // "" or "{id}"

		if !withID && path != "" {
			http.NotFound(w, r)
			return
		}
		if withID && path == "" {
			http.NotFound(w, r)
			return
		}

		switch r.Method {
		case http.MethodGet:
			if withID {
				handleGetDomainByID(w, r, repo, path)
			} else {
				handleListDomains(w, r, repo)
			}
		case http.MethodPost:
			if withID {
				http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
				return
			}
			handleCreateDomain(w, r, repo)
		case http.MethodPatch:
			if !withID {
				http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
				return
			}
			handlePatchDomain(w, r, repo, path)
		case http.MethodDelete:
			if !withID {
				http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
				return
			}
			handleDeleteDomain(w, r, repo, path)
		default:
			http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		}
	}
}

func handleListDomains(w http.ResponseWriter, r *http.Request, repo *storage.Repository) {
	domains, err := repo.ListDomains(r.Context())
	if err != nil {
		http.Error(w, `{"error":"cannot list domains"}`, http.StatusInternalServerError)
		return
	}

	out := make([]domainListResponseItem, 0, len(domains))
	for _, d := range domains {
		out = append(out, domainListResponseItem{
			ID:        d.ID.String(),
			FQDN:      d.FQDN,
			Status:    d.Status,
			DeviceID:  d.DeviceID.String(),
			CreatedAt: d.CreatedAt,
		})
	}
	_ = json.NewEncoder(w).Encode(out)
}

func handleGetDomainByID(w http.ResponseWriter, r *http.Request, repo *storage.Repository, idStr string) {
	id, err := uuid.Parse(strings.TrimSpace(idStr))
	if err != nil {
		http.Error(w, `{"error":"invalid id"}`, http.StatusBadRequest)
		return
	}

	d, err := repo.GetDomainByID(r.Context(), id)
	if errors.Is(err, storage.ErrDomainNotFound) {
		http.Error(w, `{"error":"not found"}`, http.StatusNotFound)
		return
	}
	if err != nil {
		http.Error(w, `{"error":"cannot get domain"}`, http.StatusInternalServerError)
		return
	}

	resp := domainCreateResponse{
		ID:        d.ID.String(),
		FQDN:      d.FQDN,
		Status:    d.Status,
		DeviceID:  d.DeviceID.String(),
		CreatedAt: d.CreatedAt,
	}
	_ = json.NewEncoder(w).Encode(resp)
}

func handleCreateDomain(w http.ResponseWriter, r *http.Request, repo *storage.Repository) {
	var req domainCreateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid json"}`, http.StatusBadRequest)
		return
	}
	req.FQDN = strings.ToLower(strings.TrimSpace(req.FQDN))
	req.DeviceFingerprint = strings.TrimSpace(req.DeviceFingerprint)

	if req.FQDN == "" {
		http.Error(w, `{"error":"fqdn required"}`, http.StatusBadRequest)
		return
	}
	if req.DeviceFingerprint == "" {
		http.Error(w, `{"error":"device_fingerprint required"}`, http.StatusBadRequest)
		return
	}

	created, err := repo.RegisterDomainForFingerprint(r.Context(), req.DeviceFingerprint, req.FQDN)
	if err != nil {
		writeStorageHTTPErrorJSON(w, err)
		return
	}

	resp := domainCreateResponse{
		ID:        created.ID.String(),
		FQDN:      created.FQDN,
		Status:    created.Status,
		DeviceID:  created.DeviceID.String(),
		CreatedAt: created.CreatedAt,
	}
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(resp)
}

func handlePatchDomain(w http.ResponseWriter, r *http.Request, repo *storage.Repository, idStr string) {
	id, err := uuid.Parse(strings.TrimSpace(idStr))
	if err != nil {
		http.Error(w, `{"error":"invalid id"}`, http.StatusBadRequest)
		return
	}

	var req domainPatchRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid json"}`, http.StatusBadRequest)
		return
	}
	if strings.TrimSpace(string(req.Status)) == "" {
		http.Error(w, `{"error":"status required"}`, http.StatusBadRequest)
		return
	}

	updated, err := repo.UpdateDomainStatus(r.Context(), id, req.Status)
	if errors.Is(err, storage.ErrDomainNotFound) {
		http.Error(w, `{"error":"not found"}`, http.StatusNotFound)
		return
	}
	if err != nil {
		http.Error(w, `{"error":"cannot update domain"}`, http.StatusInternalServerError)
		return
	}

	resp := domainCreateResponse{
		ID:        updated.ID.String(),
		FQDN:      updated.FQDN,
		Status:    updated.Status,
		DeviceID:  updated.DeviceID.String(),
		CreatedAt: updated.CreatedAt,
	}
	_ = json.NewEncoder(w).Encode(resp)
}

func handleDeleteDomain(w http.ResponseWriter, r *http.Request, repo *storage.Repository, idStr string) {
	id, err := uuid.Parse(strings.TrimSpace(idStr))
	if err != nil {
		http.Error(w, `{"error":"invalid id"}`, http.StatusBadRequest)
		return
	}

	deleted, err := repo.DeleteDomainByID(r.Context(), id)
	if errors.Is(err, storage.ErrDomainNotFound) {
		http.Error(w, `{"error":"not found"}`, http.StatusNotFound)
		return
	}
	if err != nil {
		http.Error(w, `{"error":"cannot delete domain"}`, http.StatusInternalServerError)
		return
	}

	notifyUnboundDevice(deleted.FQDN)

	resp := domainCreateResponse{
		ID:        deleted.ID.String(),
		FQDN:      deleted.FQDN,
		Status:    deleted.Status,
		DeviceID:  deleted.DeviceID.String(),
		CreatedAt: deleted.CreatedAt,
	}
	_ = json.NewEncoder(w).Encode(resp)
}

func writeStorageHTTPErrorJSON(w http.ResponseWriter, err error) {
	var status int
	var msg string

	switch {
	case errors.Is(err, storage.ErrFingerprintInvalid):
		status = http.StatusBadRequest
		msg = "invalid device_fingerprint"
	case errors.Is(err, storage.ErrDomainInvalid):
		status = http.StatusBadRequest
		msg = "invalid fqdn"
	case errors.Is(err, storage.ErrDomainAlreadyUsed):
		status = http.StatusConflict
		msg = "domain already registered to another device"
	case errors.Is(err, storage.ErrDeviceRevoked):
		status = http.StatusForbidden
		msg = "device is revoked"
	default:
		status = http.StatusInternalServerError
		msg = "storage error"
	}

	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(errorResponse{Error: msg})
}
