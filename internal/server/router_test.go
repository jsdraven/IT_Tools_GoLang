// Package server tests the web server
//
// SPDX-License-Identifier: AGPL-3.0-or-later
package server

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jsdraven/IT_Tools_GoLang/internal/config"
)

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func TestHealthz(t *testing.T) {
	cfg := config.Load()
	h := NewRouter(cfg, discardLogger())

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
	h := NewRouter(cfg, discardLogger())

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
	h := NewRouter(cfg, discardLogger())

	req := httptest.NewRequest(http.MethodGet, "/nope", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for unknown route, got %d", rr.Code)
	}
}

func TestRateBan_Now_DefaultVsCustom(t *testing.T) {
	cfg := config.Load()
	rb := NewRateBan(cfg, discardLogger())

	// Custom nowFunc
	ref := time.Date(2025, 8, 10, 12, 0, 0, 0, time.UTC)
	rb.nowFunc = func() time.Time { return ref }
	if got := rb.now(); !got.Equal(ref) {
		t.Fatalf("now() custom mismatch: %v", got)
	}

	// Nil nowFunc -> real time (just verify it doesn't panic)
	rb.nowFunc = nil
	_ = rb.now()
}

func TestRateBan_IsBanned_States(t *testing.T) {
	cfg := config.Load()
	rb := NewRateBan(cfg, discardLogger())

	// none
	if b, _ := rb.isBanned("203.0.113.1"); b {
		t.Fatal("expected not banned")
	}

	// active
	now := time.Now()
	rb.mu.Lock()
	rb.bans["203.0.113.2"] = now.Add(1 * time.Minute)
	rb.mu.Unlock()
	if b, _ := rb.isBanned("203.0.113.2"); !b {
		t.Fatal("expected banned")
	}

	// expired -> auto-unban on check
	rb.mu.Lock()
	rb.bans["203.0.113.3"] = now.Add(-1 * time.Minute)
	rb.mu.Unlock()
	if b, _ := rb.isBanned("203.0.113.3"); b {
		t.Fatal("expected expired ban to be cleared")
	}
}

func TestRateBan_ExtractIP_Variants(t *testing.T) {
	cfg := config.Load()
	cfg.TrustProxy = false
	rb := NewRateBan(cfg, discardLogger())

	// No proxy: RemoteAddr host:port
	req := httptest.NewRequest(http.MethodGet, "http://svc.local/x", nil)
	req.RemoteAddr = "203.0.113.9:12345"
	if ip := rb.extractIP(req); ip != "203.0.113.9" {
		t.Fatalf("extractIP (no proxy): got %q", ip)
	}

	// With proxy + XFF single IP (no port)
	cfg.TrustProxy = true
	rb = NewRateBan(cfg, discardLogger())
	req2 := httptest.NewRequest(http.MethodGet, "http://svc.local/x", nil)
	req2.Header.Set("X-Forwarded-For", "198.51.100.10")
	if ip := rb.extractIP(req2); ip != "198.51.100.10" {
		t.Fatalf("extractIP (xff w/o port): got %q", ip)
	}

	// With proxy + XFF includes port
	req3 := httptest.NewRequest(http.MethodGet, "http://svc.local/x", nil)
	req3.Header.Set("X-Forwarded-For", "198.51.100.11:555, 198.51.100.12")
	if ip := rb.extractIP(req3); ip != "198.51.100.11" {
		t.Fatalf("extractIP (xff w/ port): got %q", ip)
	}

	// With proxy but empty XFF -> fallback to RemoteAddr
	req4 := httptest.NewRequest(http.MethodGet, "http://svc.local/x", nil)
	req4.RemoteAddr = "203.0.113.77:2222"
	if ip := rb.extractIP(req4); ip != "203.0.113.77" {
		t.Fatalf("extractIP (empty xff): got %q", ip)
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

	rb := NewRateBan(cfg, discardLogger())
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

func TestRateBan_SweepOnce_UnbanAndPrune(t *testing.T) {
	cfg := config.Load()
	cfg.BanWindowSeconds = 60
	rb := NewRateBan(cfg, discardLogger())

	now := time.Date(2025, 8, 10, 12, 0, 0, 0, time.UTC)

	// Set one expired and one active ban
	rb.mu.Lock()
	rb.bans["198.51.100.1"] = now.Add(-time.Minute) // expired
	rb.bans["198.51.100.2"] = now.Add(time.Minute)  // active
	// Hits: one old, one fresh for IP3
	old := now.Add(-2 * time.Minute)
	rb.hits["198.51.100.3"] = []time.Time{old, now.Add(-10 * time.Second)}
	rb.mu.Unlock()

	rb.sweepOnce(now)

	rb.mu.Lock()
	defer rb.mu.Unlock()
	if _, ok := rb.bans["198.51.100.1"]; ok {
		t.Fatal("expired ban not removed")
	}
	if _, ok := rb.bans["198.51.100.2"]; !ok {
		t.Fatal("active ban removed unexpectedly")
	}
	if hits := rb.hits["198.51.100.3"]; len(hits) != 1 {
		t.Fatalf("expected pruned hits len=1, got %d", len(hits))
	}
}
