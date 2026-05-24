package admin

import (
	"net/http"

	"relay/storage"
)

func ServeAPIv1(mux *http.ServeMux, repo *storage.Repository) {
	api := http.NewServeMux()

	api.Handle("/domains", requireAPIKey(http.HandlerFunc(domainsV1Handler(repo, false))))
	api.Handle("/domains/", requireAPIKey(http.HandlerFunc(domainsV1Handler(repo, true))))

	mux.Handle("/api/v1/", http.StripPrefix("/api/v1", api))
}
