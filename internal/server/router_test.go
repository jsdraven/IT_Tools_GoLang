// Package server tests the web server
//
// SPDX-License-Identifier: AGPL-3.0-or-later
package server_test

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jsdraven/IT_Tools_GoLang/internal/config"
	mwrateban "github.com/jsdraven/IT_Tools_GoLang/internal/middleware/rateban"
	"github.com/jsdraven/IT_Tools_GoLang/internal/server"
)

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func TestHealthz(t *testing.T) {
	cfg := config.Load()
	h := server.NewRouter(cfg, discardLogger())

	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	if got := strings.TrimSpace(rr.Body.String()); got != "ok" {
		t.Fatalf(`expected body "ok", got %q`, got)
	}
}

func TestRoot(t *testing.T) {
	cfg := config.Load()
	h := server.NewRouter(cfg, discardLogger())

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	if body := strings.TrimSpace(rr.Body.String()); body == "" {
		t.Fatalf("expected non-empty body for /, got empty")
	}
}

func TestNotFound(t *testing.T) {
	cfg := config.Load()
	h := server.NewRouter(cfg, discardLogger())

	req := httptest.NewRequest(http.MethodGet, "/nope", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for unknown route, got %d", rr.Code)
	}
}

func TestRateBan_Middleware_SilentDrop_Fallback(t *testing.T) {
	cfg := config.Load()
	cfg.RateLimitRPS = 0
	cfg.RateLimitBurst = 0
	cfg.BanThreshold = 1 // ban after one 429 (so 2nd request is 403)
	cfg.BanWindowSeconds = 60
	cfg.BanDurationSeconds = 60
	cfg.BanSilentDrop = true // httptest writer can't Hijack -> fallback 403

	rb := mwrateban.NewRateBan(cfg, discardLogger())
	h := rb.Middleware()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK) // should never be reached
	}))

	req := httptest.NewRequest(http.MethodGet, "http://svc.local/x", nil)
	req.RemoteAddr = "203.0.113.55:1111"

	// 1st over-limit -> 429
	rr1 := httptest.NewRecorder()
	h.ServeHTTP(rr1, req)
	if rr1.Code != http.StatusTooManyRequests {
		t.Fatalf("want 429 first, got %d", rr1.Code)
	}
	// 2nd -> banned; since no Hijacker, expect 403
	rr2 := httptest.NewRecorder()
	h.ServeHTTP(rr2, req)
	if rr2.Code != http.StatusForbidden {
		t.Fatalf("want 403 after ban (no hijack), got %d", rr2.Code)
	}
}
