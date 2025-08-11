// Package server - tests for security/cors middleware.
// SPDX-License-Identifier: AGPL-3.0-or-later
package server

import (
	"crypto/tls"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jsdraven/IT_Tools_GoLang/internal/config"
)

func nextOK() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
}

func TestSecurityHeaders_TLS_WithHSTS(t *testing.T) {
	cfg := config.Load()
	cfg.HSTSEnable = true
	cfg.HSTSMaxAgeSeconds = 63072000
	cfg.CSPReportOnly = false

	h := SecurityHeaders(cfg)(nextOK())

	req := httptest.NewRequest(http.MethodGet, "https://example.com/x", nil)
	// mark as TLS so HSTS path is exercised
	req.TLS = &tls.ConnectionState{}
	rr := httptest.NewRecorder()

	h.ServeHTTP(rr, req)

	if got := rr.Header().Get("Content-Security-Policy"); !strings.Contains(got, "default-src 'self'") {
		t.Fatalf("expected CSP header, got %q", got)
	}
	if rr.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Fatalf("missing/incorrect X-Content-Type-Options")
	}
	if rr.Header().Get("X-Frame-Options") != "DENY" {
		t.Fatalf("missing/incorrect X-Frame-Options")
	}
	if !strings.Contains(rr.Header().Get("Strict-Transport-Security"), "max-age=63072000") {
		t.Fatalf("expected HSTS max-age, got %q", rr.Header().Get("Strict-Transport-Security"))
	}
}

func TestSecurityHeaders_CSP_ReportOnly(t *testing.T) {
	cfg := config.Load()
	cfg.CSPReportOnly = true

	h := SecurityHeaders(cfg)(nextOK())

	req := httptest.NewRequest(http.MethodGet, "http://example.com/x", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Header().Get("Content-Security-Policy") != "" {
		t.Fatalf("CSP should not be enforced when Report-Only is set")
	}
	if got := rr.Header().Get("Content-Security-Policy-Report-Only"); !strings.Contains(got, "default-src 'self'") {
		t.Fatalf("expected CSP-Report-Only, got %q", got)
	}
}

func TestCORS_Preflight_AllowedOrigin(t *testing.T) {
	origin := "http://allowed.local"
	cfg := config.Load()
	cfg.CORSAllowedOrigins = []string{origin}
	cfg.CORSAllowCreds = true

	h := CORS(cfg)(nextOK())

	req := httptest.NewRequest(http.MethodOptions, "http://svc.local/api", nil)
	req.Header.Set("Origin", origin)
	req.Header.Set("Access-Control-Request-Method", "GET")
	rr := httptest.NewRecorder()

	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusNoContent {
		t.Fatalf("preflight expected 204, got %d", rr.Code)
	}
	if rr.Header().Get("Access-Control-Allow-Origin") != origin {
		t.Fatalf("missing/incorrect ACAO")
	}
	if rr.Header().Get("Access-Control-Allow-Credentials") != "true" {
		t.Fatalf("missing/incorrect ACAC")
	}
	if rr.Header().Get("Access-Control-Allow-Methods") == "" {
		t.Fatalf("missing ACAM")
	}
}

func TestCORS_Preflight_NotAllowedOrigin(t *testing.T) {
	cfg := config.Load()
	cfg.CORSAllowedOrigins = []string{"http://allowed.local"} // different than request

	h := CORS(cfg)(nextOK())

	req := httptest.NewRequest(http.MethodOptions, "http://svc.local/api", nil)
	req.Header.Set("Origin", "http://not-allowed.local")
	req.Header.Set("Access-Control-Request-Method", "GET")
	rr := httptest.NewRecorder()

	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusNoContent {
		t.Fatalf("expected 204 for preflight when not allowed, got %d", rr.Code)
	}
	if rr.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Fatalf("should not set ACAO for disallowed origin")
	}
}

func TestRequireHTTPS_RedirectsPlainHTTP(t *testing.T) {
	cfg := config.Load()
	cfg.HTTPSRedirect = true

	h := RequireHTTPS(cfg)(nextOK())

	req := httptest.NewRequest(http.MethodGet, "http://example.com/path?q=1", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusPermanentRedirect {
		t.Fatalf("expected 308 redirect, got %d", rr.Code)
	}
	loc := rr.Header().Get("Location")
	if loc != "https://example.com/path?q=1" {
		t.Fatalf("unexpected redirect location: %q", loc)
	}
}

func TestAllowedHosts(t *testing.T) {
	cfg := config.Load()
	cfg.AllowedHosts = []string{"svc.local:8080"}

	h := AllowedHosts(cfg)(nextOK())

	// allowed
	req := httptest.NewRequest(http.MethodGet, "http://svc.local:8080/x", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("allowed host should pass, got %d", rr.Code)
	}

	// denied
	req2 := httptest.NewRequest(http.MethodGet, "http://evil.local:8080/x", nil)
	rr2 := httptest.NewRecorder()
	h.ServeHTTP(rr2, req2)
	if rr2.Code != http.StatusMisdirectedRequest {
		t.Fatalf("denied host should be 421, got %d", rr2.Code)
	}
}

func TestMaxBodyBytes(t *testing.T) {
	cfg := config.Load()
	cfg.MaxBodyBytes = 8 // tiny

	// handler that reads the body
	readAll := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	})

	h := MaxBodyBytes(cfg)(readAll)

	// under limit OK
	req := httptest.NewRequest(http.MethodPost, "http://svc.local/u", strings.NewReader("1234567"))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("under limit should pass, got %d", rr.Code)
	}

	// over Content-Length -> immediate 413
	req2 := httptest.NewRequest(http.MethodPost, "http://svc.local/u", strings.NewReader("0123456789ABC"))
	req2.ContentLength = 13
	rr2 := httptest.NewRecorder()
	h.ServeHTTP(rr2, req2)
	if rr2.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("over limit should be 413, got %d", rr2.Code)
	}
}
