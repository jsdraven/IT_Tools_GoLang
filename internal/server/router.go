// Package server constructs the HTTP router and middleware stack for the app.
// SPDX-License-Identifier: AGPL-3.0-or-later
package server

import (
	"fmt"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/jsdraven/IT_Tools_GoLang/internal/config"
	log "github.com/jsdraven/IT_Tools_GoLang/internal/log"
	mwrateban "github.com/jsdraven/IT_Tools_GoLang/internal/middleware/rateban"
	mws "github.com/jsdraven/IT_Tools_GoLang/internal/middleware/security"
)

// NewRouter builds the chi router with security/cors/logging middleware.
func NewRouter(cfg *config.Config, logger *slog.Logger) http.Handler {
	r := chi.NewRouter()

	// Robust defaults
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Recoverer)
	r.Use(middleware.Timeout(60 * time.Second))

	// Rate-limit + auto-ban
	rb := mwrateban.NewRateBan(cfg, logger)
	r.Use(rb.Middleware())

	// Security & CORS
	r.Use(mws.RequireHTTPS(cfg))
	r.Use(mws.AllowedHosts(cfg))
	r.Use(mws.MaxBodyBytes(cfg))
	r.Use(mws.Headers(cfg))
	r.Use(mws.CORS(cfg))

	// Structured request logging
	r.Use(log.Middleware(cfg, logger))

	// Health
	r.Get("/healthz", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "ok")
	})

	// Root
	r.Get("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "IT_Tools_GoLang is running")
	})

	// (optional) demo download endpoint you can delete later.
	// Hits:  GET /download/{name}
	// Serves a file from ./downloads/{name} with safe headers and strict length.
	r.Get("/download/{name}", func(w http.ResponseWriter, r *http.Request) {
		name := chi.URLParam(r, "name")
		// very small allowlist demo: strip path separators
		if strings.Contains(name, "/") || strings.Contains(name, "\\") {
			http.Error(w, "invalid filename", http.StatusBadRequest)
			return
		}
		path := filepath.Join("downloads", name)
		f, err := os.Open(path)
		if err != nil {
			if os.IsNotExist(err) {
				http.NotFound(w, r)
				return
			}
			http.Error(w, "error opening file", http.StatusInternalServerError)
			return
		}
		defer f.Close()
		st, err := f.Stat()
		if err != nil || !st.Mode().IsRegular() {
			http.Error(w, "unreadable file", http.StatusBadRequest)
			return
		}
		// best-effort type from extension; fall back to octet-stream
		ct := mime.TypeByExtension(filepath.Ext(name))
		if ct == "" {
			ct = "application/octet-stream"
		}
		if err := WriteSafeDownload(w, r, name, st.Size(), f, ct); err != nil {
			_ = err // (optional) log it if you want
		}
	})

	// Read-only visibility into bans (optional)
	if cfg.AdminEndpointsEnable {
		r.Get("/admin/bans", rb.HandleListBans())
	}

	return r
}

// WriteSafeDownload streams a file-like response with strict headers and Range support.
// Requires the source to implement BOTH io.ReadSeeker and io.ReaderAt so we can build
// a bounded SectionReader and still satisfy ServeContent's ReadSeeker requirement.
//
// filename: suggested name for the client (used in Content-Disposition)
// size:     exact size of the payload in bytes (must be >= 0)
// ctype:    content type to set; if empty, defaults to application/octet-stream
func WriteSafeDownload(
	w http.ResponseWriter,
	r *http.Request,
	filename string,
	size int64,
	reader interface {
		io.ReadSeeker
		io.ReaderAt
	},
	ctype string,
) error {
	if size < 0 {
		http.Error(w, "unknown length", http.StatusInternalServerError)
		return fmt.Errorf("WriteSafeDownload: negative size")
	}
	if strings.TrimSpace(ctype) == "" {
		ctype = "application/octet-stream"
	}

	// Security & meta headers (nosniff is also set globally by SecurityHeaders)
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Type", ctype)
	w.Header().Set("Content-Length", strconv.FormatInt(size, 10))
	setDownloadDisposition(w, filename)

	// Bound the readable window to [0, size) and let ServeContent handle Range/HEAD.
	sec := io.NewSectionReader(reader, 0, size) // requires ReaderAt
	// SectionReader implements ReadSeeker, so ServeContent will honor Range requests.
	http.ServeContent(w, r, filename, time.Time{}, sec)
	return nil
}

// setDownloadDisposition sets Content-Disposition with an ASCII fallback and RFC5987 filename*.
func setDownloadDisposition(w http.ResponseWriter, name string) {
	ascii := makeASCIIFallback(name)
	utf8Star := "UTF-8''" + urlEncodeRFC5987(name)
	// Keep quoting minimal and escape embedded quotes/backslashes defensively.
	var b strings.Builder
	b.WriteString("attachment; filename=\"")
	for i := 0; i < len(ascii); i++ {
		c := ascii[i]
		if c == '"' || c == '\\' {
			b.WriteByte('\\')
		}
		b.WriteByte(c)
	}
	b.WriteString("\"; filename*=")
	b.WriteString(utf8Star)
	w.Header().Set("Content-Disposition", b.String())
}

// makeASCIIFallback returns a conservative ASCII-only filename for legacy user agents.
func makeASCIIFallback(s string) string {
	const ok = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-"
	var b strings.Builder
	for _, r := range s {
		if r < 128 && strings.ContainsRune(ok, r) {
			b.WriteRune(r)
			continue
		}
		b.WriteByte('_')
	}
	out := b.String()
	if out == "" {
		return "download.bin"
	}
	return out
}

// urlEncodeRFC5987 percent-encodes bytes appropriate for filename* UTF-8 form.
func urlEncodeRFC5987(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
			(c >= '0' && c <= '9') || c == '.' || c == '_' || c == '-' {
			b.WriteByte(c)
		} else {
			const hex = "0123456789ABCDEF"
			b.WriteByte('%')
			b.WriteByte(hex[c>>4])
			b.WriteByte(hex[c&0x0F])
		}
	}
	return b.String()
}
