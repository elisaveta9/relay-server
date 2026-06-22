package admin

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"relay/storage"
)

type domainListResponseItem struct {
	ID                string               `json:"id"`
	FQDN              string               `json:"fqdn"`
	Status            storage.DomainStatus `json:"status"`
	DeviceID          string               `json:"device_id"`
	DeviceFingerprint string               `json:"device_fingerprint"`
	CreatedAt         time.Time            `json:"created_at"`
}

type domainListResponse struct {
	Items      []domainListResponseItem `json:"items"`
	Page       int                      `json:"page"`
	PerPage    int                      `json:"per_page"`
	Total      int64                    `json:"total"`
	TotalPages int                      `json:"total_pages"`
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
	options, err := domainListOptionsFromRequest(r)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		writeJSONResponse(w, errorResponse{Error: err.Error()})
		return
	}

	page, err := repo.ListDomainsFiltered(r.Context(), options)
	if err != nil {
		http.Error(w, `{"error":"cannot list domains"}`, http.StatusInternalServerError)
		return
	}

	out := make([]domainListResponseItem, 0, len(page.Domains))
	for _, d := range page.Domains {
		out = append(out, domainListResponseItem{
			ID:                d.ID.String(),
			FQDN:              d.FQDN,
			Status:            adminDomainStatus(d.Status),
			DeviceID:          d.DeviceID.String(),
			DeviceFingerprint: d.Device.CertFingerprint,
			CreatedAt:         d.CreatedAt,
		})
	}
	totalPages := 0
	if page.Total > 0 {
		totalPages = int((page.Total + int64(page.PerPage) - 1) / int64(page.PerPage))
	}
	writeJSONResponse(w, domainListResponse{
		Items:      out,
		Page:       page.Page,
		PerPage:    page.PerPage,
		Total:      page.Total,
		TotalPages: totalPages,
	})
}

func domainListOptionsFromRequest(r *http.Request) (storage.DomainListOptions, error) {
	query := r.URL.Query()
	options := storage.DomainListOptions{
		Page:    1,
		PerPage: 50,
		Search:  query.Get("q"),
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
		status := storage.DomainStatus(raw)
		switch status {
		case storage.DomainStatusRegistered, storage.DomainStatusDisabled:
			options.Status = &status
		default:
			return options, errors.New("invalid status")
		}
	}
	if raw := strings.TrimSpace(query.Get("device")); raw != "" {
		if id, err := uuid.Parse(raw); err == nil {
			options.DeviceID = &id
		} else {
			options.Fingerprint = raw
		}
	}

	if raw := strings.TrimSpace(query.Get("from")); raw != "" {
		value, err := parseDomainDateFilter(raw, false)
		if err != nil {
			return options, errors.New("invalid from date")
		}
		options.CreatedFrom = &value
	}
	if raw := strings.TrimSpace(query.Get("to")); raw != "" {
		value, err := parseDomainDateFilter(raw, true)
		if err != nil {
			return options, errors.New("invalid to date")
		}
		options.CreatedTo = &value
	}
	return options, nil
}

func parseDomainDateFilter(raw string, endOfDay bool) (time.Time, error) {
	if value, err := time.Parse("2006-01-02", raw); err == nil {
		if endOfDay {
			value = value.Add(24 * time.Hour)
		}
		return value.UTC(), nil
	}
	value, err := time.Parse(time.RFC3339, raw)
	if err != nil {
		return time.Time{}, err
	}
	return value.UTC(), nil
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
		Status:    adminDomainStatus(d.Status),
		DeviceID:  d.DeviceID.String(),
		CreatedAt: d.CreatedAt,
	}
	writeJSONResponse(w, resp)
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
		Status:    adminDomainStatus(created.Status),
		DeviceID:  created.DeviceID.String(),
		CreatedAt: created.CreatedAt,
	}
	w.WriteHeader(http.StatusCreated)
	writeJSONResponse(w, resp)
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
	if updated.Status == storage.DomainStatusDisabled {
		notifyUnboundDevice(repo, updated.FQDN, "domain disabled")
	}

	resp := domainCreateResponse{
		ID:        updated.ID.String(),
		FQDN:      updated.FQDN,
		Status:    adminDomainStatus(updated.Status),
		DeviceID:  updated.DeviceID.String(),
		CreatedAt: updated.CreatedAt,
	}
	writeJSONResponse(w, resp)
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

	notifyUnboundDevice(repo, deleted.FQDN, "domain deleted")

	resp := domainCreateResponse{
		ID:        deleted.ID.String(),
		FQDN:      deleted.FQDN,
		Status:    adminDomainStatus(deleted.Status),
		DeviceID:  deleted.DeviceID.String(),
		CreatedAt: deleted.CreatedAt,
	}
	writeJSONResponse(w, resp)
}

func adminDomainStatus(status storage.DomainStatus) storage.DomainStatus {
	if status == storage.DomainStatusBound {
		return storage.DomainStatusRegistered
	}
	return status
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
	case errors.Is(err, storage.ErrDomainLimitReached):
		status = http.StatusConflict
		msg = "device domain limit reached"
	default:
		status = http.StatusInternalServerError
		msg = "storage error"
	}

	w.WriteHeader(status)
	writeJSONResponse(w, errorResponse{Error: msg})
}

func writeJSONResponse(w http.ResponseWriter, value any) {
	if err := json.NewEncoder(w).Encode(value); err != nil {
		log.Printf("write JSON response failed: %v", err)
	}
}
