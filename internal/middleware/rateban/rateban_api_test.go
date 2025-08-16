// SPDX-License-Identifier: AGPL-3.0-or-later
package rateban_test

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jsdraven/IT_Tools_GoLang/internal/config"
	mwrateban "github.com/jsdraven/IT_Tools_GoLang/internal/middleware/rateban"
)

func discardLogger() *slog.Logger {
	return slog.New(slog.NewJSONHandler(io.Discard, nil))
}

func TestRateBan_BanAfterThreshold(t *testing.T) {
	cfg := config.Load()
	cfg.RateLimitRPS = 0
	cfg.RateLimitBurst = 0
	cfg.BanThreshold = 3
	cfg.BanWindowSeconds = 60
	cfg.BanDurationSeconds = 60
	cfg.BanSilentDrop = false // send a status for test determinism

	rb := mwrateban.NewRateBan(cfg, discardLogger())
	h := rb.Middleware()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "http://svc.local/x", nil)
	req.RemoteAddr = "203.0.113.9:12345"

	// First 3: rate-limited (429)
	for i := 0; i < cfg.BanThreshold; i++ {
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		if rr.Code != http.StatusTooManyRequests {
			t.Fatalf("want 429 on hit %d, got %d", i+1, rr.Code)
		}
	}

	// Next one: banned (403)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("want 403 after ban, got %d", rr.Code)
	}
}

func TestRateBan_ListBans(t *testing.T) {
	cfg := config.Load()
	cfg.RateLimitRPS = 0
	cfg.RateLimitBurst = 0
	cfg.BanThreshold = 1
	cfg.BanWindowSeconds = 60
	cfg.BanDurationSeconds = 60
	cfg.AdminEndpointsEnable = true

	rb := mwrateban.NewRateBan(cfg, discardLogger())
	hList := rb.HandleListBans()
	hMW := rb.Middleware()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "http://svc.local/x", nil)
	req.RemoteAddr = "198.51.100.7:54321"

	// With "ban after threshold", we need one extra over-limit request.
	rr1 := httptest.NewRecorder()
	hMW.ServeHTTP(rr1, req) // 1st over-limit → 429
	rr1b := httptest.NewRecorder()
	hMW.ServeHTTP(rr1b, req) // 2nd over-limit → ban applied (403)

	// List should include the IP
	rr2 := httptest.NewRecorder()
	hList.ServeHTTP(rr2, httptest.NewRequest(http.MethodGet, "http://svc.local/admin/bans", nil))
	if rr2.Code != http.StatusOK || rr2.Body.Len() == 0 {
		t.Fatalf("list bans failed: code=%d body=%q", rr2.Code, rr2.Body.String())
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
