package admin

import (
	"net/http"

	"relay/storage"
)

func ServeAPIv1(mux *http.ServeMux, repo *storage.Repository) {
	api := http.NewServeMux()

	api.Handle("/csrf", requireAPIKey(http.HandlerFunc(csrfTokenHandler)))
	api.Handle("/domains", requireAPIKey(requireCSRF(http.HandlerFunc(domainsV1Handler(repo, false)))))
	api.Handle("/domains/", requireAPIKey(requireCSRF(http.HandlerFunc(domainsV1Handler(repo, true)))))
	api.Handle("/devices", requireAPIKey(http.HandlerFunc(devicesV1Handler(repo, false))))
	api.Handle("/devices/", requireAPIKey(requireCSRF(http.HandlerFunc(devicesV1Handler(repo, true)))))
	api.Handle("/sessions", requireAPIKey(http.HandlerFunc(sessionsV1Handler(repo))))
	api.Handle("/logs", requireAPIKey(http.HandlerFunc(logsV1Handler())))

	mux.Handle("/api/v1/", http.StripPrefix("/api/v1", api))
}
