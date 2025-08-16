// Package log provides application logging and related HTTP middleware.
package log

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

// Middleware is a slog middleware using chi's WrapResponseWriter to capture status.
// It provides sanitization and security features based on the application config.
func Middleware(cfg *config.Config, logger *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			path := pathOf(r, cfg.LogIncludeQuery)
			if shouldSkip(path, cfg.LogSkipPaths) {
				next.ServeHTTP(w, r)
				return
			}

			ww := middleware.NewWrapResponseWriter(w, r.ProtoMajor)
			start := time.Now()

			next.ServeHTTP(ww, r)

			ipLabel, ipVal := ipForLog(r, cfg)
			fields := []any{
				"method", r.Method,
				"path", path,
				"status", ww.Status(),
				"bytes", ww.BytesWritten(),
				"duration_ms", time.Since(start).Milliseconds(),
				ipLabel, ipVal,
				"request_id", middleware.GetReqID(r.Context()),
			}

			if hs := pickHeaders(r.Header, cfg); hs != nil {
				fields = append(fields, "headers", hs)
			}

			logger.Info("http_request", fields...)
		})
	}
}

// --- Internal Helpers ("Probe Points") ---

// pathOf decides whether to log the request URI (with query) or just the path.
func pathOf(r *http.Request, includeQuery bool) string {
	if includeQuery {
		return r.URL.RequestURI()
	}
	return r.URL.Path
}

// shouldSkip checks if the request path matches any of the configured skip prefixes.
func shouldSkip(path string, skipPaths []string) bool {
	for _, pref := range skipPaths {
		pref = strings.TrimSpace(pref)
		if pref != "" && strings.HasPrefix(path, pref) {
			return true
		}
	}
	return false
}

// extractIP gets the client IP, respecting TrustProxy (X-Forwarded-For) or RemoteAddr.
func extractIP(r *http.Request, trustProxy bool) string {
	if trustProxy {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			// Take the first IP in the list
			parts := strings.Split(xff, ",")
			ip := strings.TrimSpace(parts[0])
			// Check if it's a valid host (strips port if present)
			if h, _, err := net.SplitHostPort(ip); err == nil && h != "" {
				return h
			}
			return ip
		}
	}
	// Fallback to RemoteAddr (strips port)
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// ipForLog determines the label and value for the IP address in the log, hashing if configured.
func ipForLog(r *http.Request, cfg *config.Config) (label string, value any) {
	ip := extractIP(r, cfg.TrustProxy)
	if !cfg.LogHashIPs {
		return "remote", ip
	}
	sum := sha256.Sum256([]byte(cfg.LogIPHashSalt + ip))
	return "remote_hash", hex.EncodeToString(sum[:16]) // 128-bit prefix
}

// pickHeaders builds a compact header map based on allowlist/redact rules.
func pickHeaders(hdr http.Header, cfg *config.Config) map[string]string {
	// Precompute maps for faster lookups (could be done once outside the request path)
	allowed := make(map[string]struct{}, len(cfg.LogAllowedHeaders))
	for _, h := range cfg.LogAllowedHeaders {
		allowed[strings.ToLower(strings.TrimSpace(h))] = struct{}{}
	}
	if len(allowed) == 0 {
		return nil
	}
	redact := make(map[string]struct{}, len(cfg.LogRedactHeaders))
	for _, h := range cfg.LogRedactHeaders {
		redact[strings.ToLower(strings.TrimSpace(h))] = struct{}{}
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
