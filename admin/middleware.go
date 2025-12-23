package admin

import (
	"net/http"
)

func requireAPIKey(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key := r.Header.Get("apikey")
		ip := r.RemoteAddr

		if key == "" {
			adminLogger.Printf("ADMIN AUTH_MISSING ip=%s", ip)
			http.Error(w, "missing api key", http.StatusUnauthorized)
			return
		}

		if key != ApiKey {
			adminLogger.Printf("ADMIN AUTH_FAIL ip=%s", ip)
			http.Error(w, "invalid api key", http.StatusForbidden)
			return
		}

		next.ServeHTTP(w, r)
	})
}
