// Package server constructs the HTTP router and middleware stack for the app.
// SPDX-License-Identifier: AGPL-3.0-or-later
package server

import (
	"fmt"
	"log/slog"
	"mime"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/jsdraven/IT_Tools_GoLang/pkg/config"
	"github.com/jsdraven/IT_Tools_GoLang/pkg/download"
	log "github.com/jsdraven/IT_Tools_GoLang/pkg/logging"
	mwrateban "github.com/jsdraven/IT_Tools_GoLang/pkg/middleware/rateban"
	mws "github.com/jsdraven/IT_Tools_GoLang/pkg/middleware/security"
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
		if err := download.WriteSafeDownload(w, r, name, st.Size(), f, ct); err != nil {
			_ = err // (optional) log it if you want
		}
	})

	// Read-only visibility into bans (optional)
	if cfg.AdminEndpointsEnable {
		r.Get("/admin/bans", rb.HandleListBans())
	}

	return r
}
