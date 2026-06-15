package admin

import (
	"crypto/sha256"
	"crypto/subtle"
	"net/http"
	"strings"
)

func requireAPIKey(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key, ok := bearerToken(r.Header.Get("Authorization"))
		ip := r.RemoteAddr

		if !ok {
			logAdmin("ADMIN AUTH_MISSING ip=%s", ip)
			w.Header().Set("WWW-Authenticate", `Bearer realm="admin"`)
			http.Error(w, "missing api key", http.StatusUnauthorized)
			return
		}

		if !constantTimeEqual(key, ApiKey) {
			logAdmin("ADMIN AUTH_FAIL ip=%s", ip)
			http.Error(w, "invalid api key", http.StatusForbidden)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func constantTimeEqual(left string, right string) bool {
	leftHash := sha256.Sum256([]byte(left))
	rightHash := sha256.Sum256([]byte(right))
	return subtle.ConstantTimeCompare(leftHash[:], rightHash[:]) == 1
}

func bearerToken(value string) (string, bool) {
	scheme, token, ok := strings.Cut(value, " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") || token == "" ||
		strings.TrimSpace(token) != token || strings.ContainsAny(token, " \t\r\n") {
		return "", false
	}
	return token, true
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Strict-Transport-Security", "max-age=31536000")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set(
			"Content-Security-Policy",
			"default-src 'self'; script-src 'self'; style-src 'self'; "+
				"img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'; "+
				"frame-ancestors 'none'; form-action 'self'",
		)
		next.ServeHTTP(w, r)
	})
}

func logAdmin(format string, args ...any) {
	if adminLogger != nil {
		adminLogger.Printf(format, args...)
	}
}
