// Package security: security & CORS middleware.
// SPDX-License-Identifier: AGPL-3.0-or-later
package security

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/jsdraven/IT_Tools_GoLang/internal/config"
)

// Headers returns middleware that sets strict security headers.
// Very strict CSP; adjust if you later allow CDNs or inline scripts.
func Headers(cfg *config.Config) func(http.Handler) http.Handler {
	// Very strict baseline CSP; includes connect-src 'self' (allows same-origin XHR/WS).
	// Add "wss:" to connect-src if you serve WebSockets on different schemes.
	csp := "default-src 'self'; " +
		"base-uri 'self'; " +
		"frame-ancestors 'none'; " +
		"object-src 'none'; " +
		"img-src 'self' data:; " +
		"script-src 'self'; " +
		"style-src 'self'; " +
		"connect-src 'self'"

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Core modern headers
			if cfg.CSPReportOnly {
				w.Header().Set("Content-Security-Policy-Report-Only", csp)
			} else {
				w.Header().Set("Content-Security-Policy", csp)
			}
			w.Header().Set("Referrer-Policy", "no-referrer")
			w.Header().Set("X-Content-Type-Options", "nosniff")
			w.Header().Set("X-Frame-Options", "DENY") // redundant with CSP frame-ancestors
			w.Header().Set("Permissions-Policy", "accelerometer=(), camera=(), geolocation=(), gyroscope=(), microphone=(), payment=(), usb=(), publickey-credentials-get=()")
			w.Header().Set("Cross-Origin-Opener-Policy", "same-origin")
			w.Header().Set("Cross-Origin-Resource-Policy", "same-origin")

			// HSTS only on HTTPS responses and only if enabled
			if cfg.HSTSEnable && r.TLS != nil {
				val := "max-age=0"
				if cfg.HSTSMaxAgeSeconds > 0 {
					val = "max-age=" + strconv.Itoa(cfg.HSTSMaxAgeSeconds)
				}
				if cfg.HSTSIncludeSubDom {
					val += "; includeSubDomains"
				}
				if cfg.HSTSPreload {
					val += "; preload"
				}
				w.Header().Set("Strict-Transport-Security", val)
			}

			next.ServeHTTP(w, r)
		})
	}
}

// CORS handles preflight and sets allow headers for allowed origins only.
// Empty cfg.CORSAllowedOrigins => same-origin-only (no CORS).
func CORS(cfg *config.Config) func(http.Handler) http.Handler {
	allowed := map[string]struct{}{}
	for _, o := range cfg.CORSAllowedOrigins {
		allowed[o] = struct{}{}
	}

	allowMethods := "GET, POST, PUT, PATCH, DELETE, OPTIONS"
	allowHeaders := "Accept, Content-Type, Authorization"

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			origin := r.Header.Get("Origin")
			if origin == "" {
				// Not a CORS request
				next.ServeHTTP(w, r)
				return
			}

			// Vary to avoid cache poisoning
			w.Header().Add("Vary", "Origin")
			w.Header().Add("Vary", "Access-Control-Request-Method")
			w.Header().Add("Vary", "Access-Control-Request-Headers")

			if _, ok := allowed[origin]; !ok || len(allowed) == 0 {
				// Not allowed; behave as same-origin-only
				if r.Method == http.MethodOptions {
					w.WriteHeader(http.StatusNoContent)
					return
				}
				next.ServeHTTP(w, r)
				return
			}

			// Allowed origin
			w.Header().Set("Access-Control-Allow-Origin", origin)
			if cfg.CORSAllowCreds {
				w.Header().Set("Access-Control-Allow-Credentials", "true")
			}

			if r.Method == http.MethodOptions {
				// Preflight
				w.Header().Set("Access-Control-Allow-Methods", allowMethods)
				w.Header().Set("Access-Control-Allow-Headers", allowHeaders)
				w.WriteHeader(http.StatusNoContent)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// RequireHTTPS redirects plain HTTP to HTTPS if enabled in config.
// Works best when also listening on :80; for reverse proxies, prefer upstream redirect.
func RequireHTTPS(cfg *config.Config) func(http.Handler) http.Handler {
	if !cfg.HTTPSRedirect {
		// no-op
		return func(next http.Handler) http.Handler { return next }
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.TLS == nil {
				target := "https://" + r.Host + r.URL.RequestURI()
				http.Redirect(w, r, target, http.StatusPermanentRedirect)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// AllowedHosts enforces an allowlist of Host headers (if configured).
func AllowedHosts(cfg *config.Config) func(http.Handler) http.Handler {
	allowed := map[string]struct{}{}
	for _, h := range cfg.AllowedHosts {
		allowed[strings.ToLower(h)] = struct{}{}
	}
	if len(allowed) == 0 {
		// no-op when not configured
		return func(next http.Handler) http.Handler { return next }
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			host := strings.ToLower(r.Host)
			if _, ok := allowed[host]; !ok {
				http.Error(w, "invalid host", http.StatusMisdirectedRequest) // 421
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// MaxBodyBytes limits request size. If Content-Length exceeds limit, returns 413.
// Otherwise wraps the body so downstream reads are capped.
func MaxBodyBytes(cfg *config.Config) func(http.Handler) http.Handler {
	limit := cfg.MaxBodyBytes
	if limit <= 0 {
		return func(next http.Handler) http.Handler { return next }
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.ContentLength > 0 && r.ContentLength > limit {
				http.Error(w, "payload too large", http.StatusRequestEntityTooLarge)
				return
			}
			r.Body = http.MaxBytesReader(w, r.Body, limit)
			w.Header().Set("X-Content-Length-Limit", strconv.FormatInt(limit, 10))
			next.ServeHTTP(w, r)
		})
	}
}
