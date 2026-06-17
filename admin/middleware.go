package admin

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"

	"relay/auditlog"
)

const csrfCookieName = "__Host-relay_csrf"

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

func requireCSRF(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet, http.MethodHead, http.MethodOptions:
			next.ServeHTTP(w, r)
			return
		}

		cookie, err := r.Cookie(csrfCookieName)
		headerToken := strings.TrimSpace(r.Header.Get("X-CSRF-Token"))
		if err != nil || cookie.Value == "" || headerToken == "" ||
			!constantTimeEqual(cookie.Value, headerToken) {
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.WriteHeader(http.StatusForbidden)
			_ = json.NewEncoder(w).Encode(errorResponse{Error: "invalid csrf token"})
			return
		}

		next.ServeHTTP(w, r)
	})
}

func csrfTokenHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		http.Error(w, `{"error":"cannot create csrf token"}`, http.StatusInternalServerError)
		return
	}
	token := base64.RawURLEncoding.EncodeToString(raw[:])
	http.SetCookie(w, &http.Cookie{
		Name:     csrfCookieName,
		Value:    token,
		Path:     "/",
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   3600,
	})
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(struct {
		Token string `json:"token"`
	}{Token: token})
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
	auditlog.Printf(format, args...)
}
