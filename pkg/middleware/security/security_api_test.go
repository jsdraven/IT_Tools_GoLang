// Package security_test - tests for security/cors middleware.
// SPDX-License-Identifier: AGPL-3.0-or-later
package security_test

import (
	"bytes"
	"crypto/tls"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jsdraven/IT_Tools_GoLang/pkg/config"
	mwsecurity "github.com/jsdraven/IT_Tools_GoLang/pkg/middleware/security"
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

	h := mwsecurity.Headers(cfg)(nextOK())

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

	h := mwsecurity.Headers(cfg)(nextOK())

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

	h := mwsecurity.CORS(cfg)(nextOK())

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

	h := mwsecurity.CORS(cfg)(nextOK())

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

	h := mwsecurity.RequireHTTPS(cfg)(nextOK())

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

	h := mwsecurity.AllowedHosts(cfg)(nextOK())

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

	h := mwsecurity.MaxBodyBytes(cfg)(readAll)

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

func TestSecurityHeaders_NoHSTS_OnHTTP_EvenWhenEnabled(t *testing.T) {
	cfg := config.Load()
	cfg.HSTSEnable = true
	cfg.HSTSMaxAgeSeconds = 31536000

	h := mwsecurity.Headers(cfg)(nextOK())

	// Plain HTTP request (no TLS) → should NOT emit HSTS
	req := httptest.NewRequest(http.MethodGet, "http://example.com/x", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if got := rr.Header().Get("Strict-Transport-Security"); got != "" {
		t.Fatalf("expected no HSTS on HTTP, got %q", got)
	}
}

func TestCORS_SimpleRequest_AllowedOrigin(t *testing.T) {
	origin := "https://allowed.local"
	cfg := config.Load()
	cfg.CORSAllowedOrigins = []string{origin}
	cfg.CORSAllowCreds = true

	h := mwsecurity.CORS(cfg)(nextOK())

	// Simple GET with Origin (not preflight)
	req := httptest.NewRequest(http.MethodGet, "https://svc.local/data", nil)
	req.Header.Set("Origin", origin)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 for allowed simple request, got %d", rr.Code)
	}
	if rr.Header().Get("Access-Control-Allow-Origin") != origin {
		t.Fatalf("missing/incorrect ACAO")
	}
	if rr.Header().Get("Access-Control-Allow-Credentials") != "true" {
		t.Fatalf("missing/incorrect ACAC")
	}
}

func TestCORS_SimpleRequest_NotAllowedOrigin(t *testing.T) {
	cfg := config.Load()
	cfg.CORSAllowedOrigins = []string{"https://allowed.local"}

	h := mwsecurity.CORS(cfg)(nextOK())

	req := httptest.NewRequest(http.MethodGet, "https://svc.local/data", nil)
	req.Header.Set("Origin", "https://not-allowed.local")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("disallowed origin (simple) should still pass to handler, got %d", rr.Code)
	}
	if rr.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Fatalf("ACAO should not be set for disallowed origin")
	}
}

func TestRequireHTTPS_NoRedirectWhenAlreadyTLS(t *testing.T) {
	cfg := config.Load()
	cfg.HTTPSRedirect = true

	h := mwsecurity.RequireHTTPS(cfg)(nextOK())

	req := httptest.NewRequest(http.MethodGet, "https://example.com/secure", nil)
	req.TLS = &tls.ConnectionState{} // simulate HTTPS
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("HTTPS request should not redirect, got %d", rr.Code)
	}
}

func TestMaxBodyBytes_StreamOverLimit_WithoutContentLength(t *testing.T) {
	cfg := config.Load()
	cfg.MaxBodyBytes = 8 // tiny limit

	readAll := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "payload too large", http.StatusRequestEntityTooLarge)
			return
		}
		w.WriteHeader(http.StatusOK)
	})

	h := mwsecurity.MaxBodyBytes(cfg)(readAll)

	// No Content-Length header; body is larger than limit
	body := bytes.NewBufferString("0123456789ABC") // 13 bytes
	req := httptest.NewRequest(http.MethodPost, "http://svc.local/u", body)
	req.ContentLength = -1 // explicitly unknown (net/http sets -1 for unknown)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	// MaxBytesReader should cause a 413 before handler can write 200
	if rr.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("expected 413 for streamed over-limit body, got %d", rr.Code)
	}
}
