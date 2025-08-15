package entry

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jsdraven/IT_Tools_GoLang/internal/config"
)

// ADD: redirect handler preserves non-default HTTPS ports (e.g., :8080)
func TestRedirectToHTTPSHandler_NonDefaultPort(t *testing.T) {
	h := redirectToHTTPSHandler(":8080")

	rr := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "http://example.com/healthz?x=1", nil)
	req.Host = "example.com"

	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusPermanentRedirect {
		t.Fatalf("status: got %d, want %d", rr.Code, http.StatusPermanentRedirect)
	}
	loc := rr.Result().Header.Get("Location")
	want := "https://example.com:8080/healthz?x=1"
	if loc != want {
		t.Fatalf("Location: got %q, want %q", loc, want)
	}
}

// ADD: redirect handler strips port for default 443
func TestRedirectToHTTPSHandler_Default443(t *testing.T) {
	h := redirectToHTTPSHandler(":443")

	rr := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "http://example.com/", nil)
	// simulate incoming Host with :80 that should be stripped
	req.Host = "example.com:80"

	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusPermanentRedirect {
		t.Fatalf("status: got %d, want %d", rr.Code, http.StatusPermanentRedirect)
	}
	loc := rr.Result().Header.Get("Location")
	want := "https://example.com/"
	if loc != want {
		t.Fatalf("Location: got %q, want %q", loc, want)
	}
}

// ADD: wantHTTPRedirect auto mode behavior (env unset)
func TestWantHTTPRedirect_Auto(t *testing.T) {
	cfg := &config.Config{
		HTTPSRedirect:    false,
		HTTPSRedirectSet: false, // env unset => auto
	}
	if !wantHTTPRedirect(cfg, false /* real cert (ACME/PEM/PFX) */) {
		t.Fatal("auto mode with real cert: expected redirect=true")
	}
	if wantHTTPRedirect(cfg, true /* self-signed */) {
		t.Fatal("auto mode with self-signed: expected redirect=false")
	}
}

// ADD: wantHTTPRedirect forced on/off via env
func TestWantHTTPRedirect_ForcedOnOff(t *testing.T) {
	cfgOn := &config.Config{
		HTTPSRedirect:    true,
		HTTPSRedirectSet: true,
	}
	if !wantHTTPRedirect(cfgOn, false) || !wantHTTPRedirect(cfgOn, true) {
		t.Fatal("forced on: expected redirect=true for both real and self-signed")
	}

	cfgOff := &config.Config{
		HTTPSRedirect:    false,
		HTTPSRedirectSet: true,
	}
	if wantHTTPRedirect(cfgOff, false) || wantHTTPRedirect(cfgOff, true) {
		t.Fatal("forced off: expected redirect=false for both real and self-signed")
	}
}
