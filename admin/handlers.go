package admin

import (
	"net/http"
	"strings"

	"relay/registry"
)

func domainsHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {

	case "GET":
		registry.Global.Mu.Lock()
		defer registry.Global.Mu.Unlock()
		for d := range registry.Global.Domains {
			w.Write([]byte(d + "\n"))
		}

	case "POST":
		domain := strings.ToLower(r.URL.Query().Get("domain"))
		if domain == "" {
			http.Error(w, "domain required", http.StatusBadRequest)
			return
		}

		registry.Global.Mu.Lock()
		if _, exists := registry.Global.Domains[domain]; exists {
			w.Write([]byte("already registered\n"))
		} else {
			registry.Global.Domains[domain] = nil
			adminLogger.Printf(
				"ADMIN ADD domain=%s ip=%s",
				domain, r.RemoteAddr,
			)
			w.Write([]byte("registered\n"))
		}
		registry.Global.Mu.Unlock()

	case "DELETE":
		domain := strings.ToLower(r.URL.Query().Get("domain"))

		registry.Global.Mu.Lock()
		if _, exists := registry.Global.Domains[domain]; exists {
			delete(registry.Global.Domains, domain)
			adminLogger.Printf(
				"ADMIN DELETE domain=%s ip=%s",
				domain, r.RemoteAddr,
			)
		}
		registry.Global.Mu.Unlock()

		w.Write([]byte("deleted\n"))

	default:
		http.Error(w, "method not allowed", 405)
	}
}
