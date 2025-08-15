// Package logging: Middleware for logging sanitization and security
package logging

import (
	"crypto/sha256"
	"encoding/hex"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5/middleware"
	"github.com/jsdraven/IT_Tools_GoLang/internal/config"
)

// HTTP Logging is a slog middleware using chi's WrapResponseWriter to capture status.
func HTTP(cfg *config.Config, logger *slog.Logger) func(http.Handler) http.Handler {
	// Precompute header allowlist/redaction (lower-cased keys)
	allowed := map[string]struct{}{}
	for _, h := range cfg.LogAllowedHeaders {
		allowed[strings.ToLower(strings.TrimSpace(h))] = struct{}{}
	}
	redact := map[string]struct{}{}
	for _, h := range cfg.LogRedactHeaders {
		redact[strings.ToLower(strings.TrimSpace(h))] = struct{}{}
	}

	// Helper: get client IP respecting TrustProxy (first XFF) or RemoteAddr
	extractIP := func(r *http.Request) string {
		if cfg.TrustProxy {
			if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
				parts := strings.Split(xff, ",")
				ip := strings.TrimSpace(parts[0])
				if h, _, err := net.SplitHostPort(ip); err == nil && h != "" {
					return h
				}
				return ip
			}
		}
		host, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			return r.RemoteAddr
		}
		return host
	}

	// Helper: optionally hash IP
	hashIP := func(ip string) (label string, value any) {
		if !cfg.LogHashIPs {
			return "remote", ip
		}
		sum := sha256.Sum256([]byte(cfg.LogIPHashSalt + ip))
		return "remote_hash", hex.EncodeToString(sum[:16]) // 128-bit prefix is plenty
	}

	// Helper: decide path vs. full request URI
	pathOf := func(r *http.Request) string {
		if cfg.LogIncludeQuery {
			return r.URL.RequestURI()
		}
		return r.URL.Path
	}

	// Helper: build a compact header map based on allowlist/redact rules
	pickHeaders := func(hdr http.Header) map[string]string {
		if len(allowed) == 0 {
			return nil
		}
		out := make(map[string]string, len(allowed))
		for k, vals := range hdr {
			lk := strings.ToLower(k)
			if _, ok := allowed[lk]; !ok {
				continue
			}
			v := strings.Join(vals, ",")
			if _, red := redact[lk]; red {
				v = "[REDACTED]"
			}
			out[k] = v
		}
		if len(out) == 0 {
			return nil
		}
		return out
	}

	// Fast path check for paths we should skip entirely
	shouldSkip := func(p string) bool {
		for _, pref := range cfg.LogSkipPaths {
			pref = strings.TrimSpace(pref)
			if pref != "" && strings.HasPrefix(p, pref) {
				return true
			}
		}
		return false
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			p := pathOf(r)
			if shouldSkip(p) {
				next.ServeHTTP(w, r)
				return
			}

			ww := middleware.NewWrapResponseWriter(w, r.ProtoMajor)
			start := time.Now()

			next.ServeHTTP(ww, r)

			ipLabel, ipVal := hashIP(extractIP(r))
			fields := []any{
				"method", r.Method,
				"path", p,
				"status", ww.Status(),
				"bytes", ww.BytesWritten(),
				"duration_ms", time.Since(start).Milliseconds(),
				ipLabel, ipVal,
				"request_id", middleware.GetReqID(r.Context()),
			}

			if hs := pickHeaders(r.Header); hs != nil {
				fields = append(fields, "headers", hs)
			}

			logger.Info("http_request", fields...)
		})
	}
}
