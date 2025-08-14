// Package main tests the entrypoint helpers for booting the HTTP server.
// SPDX-License-Identifier: AGPL-3.0-or-later
package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	pkcs12modern "software.sslmate.com/src/go-pkcs12"

	"github.com/jsdraven/IT_Tools_GoLang/internal/config"
)

func discardLogger() *slog.Logger {
	return slog.New(slog.NewJSONHandler(io.Discard, nil))
}

func TestNewLogger(t *testing.T) {
	t.Helper()
	l := newLogger(slog.LevelInfo)
	if l == nil {
		t.Fatal("expected non-nil logger")
	}
}

func TestBindListener_Invalid(t *testing.T) {
	t.Helper()
	// 65536 is an invalid TCP port, should error
	_, err := bindListener("127.0.0.1:65536", discardLogger())
	if err == nil {
		t.Fatal("expected error for invalid port, got nil")
	}
}

func TestBindListener_Ephemeral(t *testing.T) {
	logger := discardLogger()
	ln, err := bindListener("127.0.0.1:0", logger)
	if err != nil {
		t.Fatalf("bindListener error: %v", err)
	}
	defer ln.Close()
	if !strings.Contains(ln.Addr().String(), ":") {
		t.Fatalf("unexpected addr: %s", ln.Addr().String())
	}
}

func TestRun_OK(t *testing.T) {
	t.Setenv("PORT", "0")
	t.Setenv("LOG_LEVEL", "ERROR")
	cfg := config.Load()

	// Use a cancellable context so we can shut the server down
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start run() in background
	done := make(chan error, 1)
	go func() { done <- run(ctx, cfg) }()

	// give it a moment to start listening
	time.Sleep(50 * time.Millisecond)

	// We don't know the exact port (PORT=0), so we can't hit it directly here,
	// but run() will exit cleanly when we cancel:
	cancel()
	select {
	case err := <-done:
		if err != nil && err != http.ErrServerClosed {
			t.Fatalf("run() returned unexpected error: %v", err)
		}
	case <-time.After(1 * time.Second):
		t.Fatal("run() did not return after cancel")
	}
}

func TestRun_BindError(t *testing.T) {
	// Force a bad addr so bindListener fails
	cfg := &config.Config{
		Addr:              "127.0.0.1:65536",
		LogLevel:          slog.LevelError,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := run(ctx, cfg); err == nil {
		t.Fatal("expected run() to error on invalid addr, got nil")
	}
}

func TestServeOnListener_ServesHealthzAndRoot(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	t.Setenv("PORT", "0") // not used when passing ln explicitly
	t.Setenv("LOG_LEVEL", "ERROR")
	cfg := config.Load()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() { errCh <- serveOnListener(ctx, ln, cfg, discardLogger()) }()

	time.Sleep(75 * time.Millisecond) // brief startup window
	// HTTPS client that accepts our self-signed cert (test-only)
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		Timeout: 2 * time.Second,
	}
	base := "https://" + ln.Addr().String()

	// /healthz should return 200
	if resp, err := client.Get(base + "/healthz"); err != nil {
		t.Fatalf("GET /healthz: %v", err)
	} else {
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status /healthz: got %d", resp.StatusCode)
		}
	}

	// / should return 200
	if resp, err := client.Get(base + "/"); err != nil {
		t.Fatalf("GET /: %v", err)
	} else {
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status /: got %d", resp.StatusCode)
		}
	}

	// shutdown
	cancel()
	select {
	case err := <-errCh:
		if err != nil && err != http.ErrServerClosed {
			t.Fatalf("serve error: %v", err)
		}
	case <-time.After(1 * time.Second):
		t.Fatal("server did not stop in time")
	}
}

func TestResolveTLS12Suites(t *testing.T) {
	out := resolveTLS12Suites([]string{
		"ECDHE-RSA-CHACHA20-POLY1305",
		"ecdhe-rsa-aes128-gcm-sha256", // alias lower-case
		"INVALID",
	})
	if len(out) == 0 {
		t.Fatalf("expected some suites to resolve")
	}
	// ensure uniqueness (no duplicates for aliases)
	seen := map[uint16]bool{}
	for _, v := range out {
		if seen[v] {
			t.Fatalf("duplicate cipher id %v", v)
		}
		seen[v] = true
	}
}

func TestGenerateCSRAndRunCSRMode(t *testing.T) {
	cfg := config.Load()
	cfg.TLSGenerateCSR = true
	cfg.TLSCSROutDir = t.TempDir()
	cfg.TLSCSRCommonName = "example.com"
	cfg.TLSCSRHosts = []string{"example.com", "127.0.0.1"}
	cfg.TLSCSROrg = "Acme Inc."

	// run() should generate CSR and return nil without starting server
	if err := run(context.Background(), cfg); err != nil {
		t.Fatalf("run(CSR mode): %v", err)
	}

	keyPath := filepath.Join(cfg.TLSCSROutDir, "server.key")
	csrPath := filepath.Join(cfg.TLSCSROutDir, "server.csr")
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatalf("read key: %v", err)
	}
	csrPEM, err := os.ReadFile(csrPath)
	if err != nil {
		t.Fatalf("read csr: %v", err)
	}
	if !pemHasType(keyPEM, "RSA PRIVATE KEY") && !pemHasType(keyPEM, "PRIVATE KEY") {
		t.Fatalf("unexpected key PEM type")
	}
	req, _ := pem.Decode(csrPEM)
	if req == nil || req.Type != "CERTIFICATE REQUEST" {
		t.Fatalf("unexpected CSR PEM type")
	}
	csr, err := x509.ParseCertificateRequest(req.Bytes)
	if err != nil {
		t.Fatalf("ParseCertificateRequest: %v", err)
	}
	if csr.Subject.CommonName != "example.com" {
		t.Fatalf("bad CSR CN: %s", csr.Subject.CommonName)
	}
	// DNSNames should include example.com
	found := false
	for _, d := range csr.DNSNames {
		if d == "example.com" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("CSR missing DNS SAN example.com")
	}
}

func pemHasType(pemBytes []byte, typ string) bool {
	block, _ := pem.Decode(pemBytes)
	return block != nil && block.Type == typ
}

// test server with self signed cert as the default state
func TestServeOnListener_SelfSignedTLS_Healthz(t *testing.T) {
	// Bind an ephemeral TCP listener
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	cfg := config.Load()
	// No ACME/PFX/PEM configured → should serve HTTPS with self-signed cert by default
	cfg.TLSAutocertEnable = false
	cfg.TLSPFXFile = ""
	cfg.TLSCertFile = ""
	cfg.TLSKeyFile = ""
	cfg.HTTPSRedirect = false

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan struct{})
	go func() {
		_ = serveOnListener(ctx, ln, cfg, newLogger(slog.LevelInfo))
		close(done)
	}()

	// Give the server a moment to start
	time.Sleep(75 * time.Millisecond)

	// HTTPS client that accepts our self-signed cert
	url := fmt.Sprintf("https://%s/healthz", ln.Addr().String())
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, // test-only
		},
		Timeout: 2 * time.Second,
	}

	resp, err := client.Get(url)
	if err != nil {
		t.Fatalf("GET /healthz (self-signed): %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("server did not shut down in time")
	}
}

// makeSelfSigned creates a self-signed RSA cert/key for CN and returns PEM paths.
func makeSelfSignedPEM(t *testing.T, cn string, dir string) (certPath, keyPath string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{cn},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})

	certPath = filepath.Join(dir, "cert.pem")
	keyPath = filepath.Join(dir, "key.pem")
	if err := os.WriteFile(certPath, certPEM, 0o600); err != nil {
		t.Fatalf("write cert: %v", err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	return certPath, keyPath
}

func TestLoadTLSFromPFX_LeafOnly(t *testing.T) {
	// Generate a self-signed cert/key in memory (same as above but keep DER objects)
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "pfx.local"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"pfx.local"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}

	// Build a minimal PFX using sslmate's encoder (test-only dep)
	pfx, err := pkcs12modern.Modern.Encode(key, cert, nil, "pass")
	if err != nil {
		t.Fatalf("pkcs12 Encode: %v", err)
	}

	dir := t.TempDir()
	p := filepath.Join(dir, "test.pfx")
	if err := os.WriteFile(p, pfx, 0o600); err != nil {
		t.Fatalf("write pfx: %v", err)
	}

	c, err := loadTLSFromPFX(p, "pass")
	if err != nil {
		t.Fatalf("loadTLSFromPFX: %v", err)
	}
	if c.Leaf == nil || c.Leaf.Subject.CommonName != "pfx.local" {
		t.Fatalf("unexpected leaf: %+v", c.Leaf)
	}
}

// ADD: ensure wrong password returns an error
func TestLoadTLSFromPFX_BadPassword(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "badpass.local"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"badpass.local"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}

	pfx, err := pkcs12modern.Modern.Encode(key, cert, nil, "correct")
	if err != nil {
		t.Fatalf("pkcs12 Encode: %v", err)
	}

	dir := t.TempDir()
	p := filepath.Join(dir, "badpass.pfx")
	if err := os.WriteFile(p, pfx, 0o600); err != nil {
		t.Fatalf("write pfx: %v", err)
	}

	// wrong password should fail
	if _, err := loadTLSFromPFX(p, "wrong"); err == nil {
		t.Fatal("expected error for wrong password, got nil")
	}
}

// ADD: ensure corrupt/garbage file returns an error
func TestLoadTLSFromPFX_CorruptFile(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "corrupt.pfx")
	// write random bytes (not a valid PKCS#12)
	data := []byte("not-a-valid-pfx\x00\x01\x02garbage")
	if err := os.WriteFile(p, data, 0o600); err != nil {
		t.Fatalf("write corrupt pfx: %v", err)
	}
	if _, err := loadTLSFromPFX(p, "irrelevant"); err == nil {
		t.Fatal("expected error for corrupt PFX, got nil")
	}
}

// ADD: ensure a chain PFX yields leaf first and includes intermediates
func TestLoadTLSFromPFX_WithChain(t *testing.T) {
	// Create a simple CA and a leaf signed by it
	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("ca key: %v", err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1001),
		Subject:               pkix.Name{CommonName: "Test Root CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create CA: %v", err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatalf("parse CA: %v", err)
	}

	leafKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("leaf key: %v", err)
	}
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2001),
		Subject:      pkix.Name{CommonName: "chain.local"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"chain.local"},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, caCert, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create leaf: %v", err)
	}
	leafCert, err := x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}

	// Encode with the CA in the chain slice
	pfx, err := pkcs12modern.Modern.Encode(leafKey, leafCert, []*x509.Certificate{caCert}, "pw")
	if err != nil {
		t.Fatalf("pkcs12 Encode: %v", err)
	}

	dir := t.TempDir()
	p := filepath.Join(dir, "chain.pfx")
	if err := os.WriteFile(p, pfx, 0o600); err != nil {
		t.Fatalf("write pfx: %v", err)
	}

	c, err := loadTLSFromPFX(p, "pw")
	if err != nil {
		t.Fatalf("loadTLSFromPFX(chain): %v", err)
	}

	if c.Leaf == nil || c.Leaf.Subject.CommonName != "chain.local" {
		t.Fatalf("unexpected leaf: %+v", c.Leaf)
	}
	if len(c.Certificate) < 2 {
		t.Fatalf("expected at least leaf+CA in chain, got %d", len(c.Certificate))
	}
	// Ensure first certificate is leaf
	if !bytes.Equal(c.Certificate[0], c.Leaf.Raw) {
		t.Fatalf("first cert is not leaf")
	}
}

func TestServeOnListener_TLS_WithPEM(t *testing.T) {
	// Bind an ephemeral listener
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	// Write a self-signed cert/key to disk
	dir := t.TempDir()
	certPath, keyPath := makeSelfSignedPEM(t, "localhost", dir)

	cfg := config.Load()
	cfg.TLSAutocertEnable = false
	cfg.TLSPFXFile = ""
	cfg.TLSCertFile = certPath
	cfg.TLSKeyFile = keyPath
	cfg.HTTPSRedirect = false // ensure we don't bounce HTTPS back to HTTPS

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan struct{})
	go func() {
		_ = serveOnListener(ctx, ln, cfg, newLogger(slog.LevelInfo))
		close(done)
	}()

	// Give the server a moment to start
	time.Sleep(75 * time.Millisecond)

	// HTTPS client that accepts our self-signed cert
	url := fmt.Sprintf("https://%s/healthz", ln.Addr().String())
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, // test-only
	}
	client := &http.Client{Transport: tr, Timeout: 2 * time.Second}

	resp, err := client.Get(url)
	if err != nil {
		t.Fatalf("GET /healthz: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("server did not shut down in time")
	}
}

func TestResolveTLS12Suites_Basic(t *testing.T) {
	out := resolveTLS12Suites([]string{
		"ECDHE-RSA-AES128-GCM-SHA256",
		"ecdhe-rsa-chacha20-poly1305",
		"INVALID",
	})
	if len(out) == 0 {
		t.Fatalf("expected some suites to resolve")
	}
}

func TestServeOnListener_FallbackToSelfSigned_WhenPFXFails(t *testing.T) {
	// Bind an ephemeral TCP listener
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	// Write a corrupt PFX to disk
	dir := t.TempDir()
	pfxPath := filepath.Join(dir, "corrupt.pfx")
	if err := os.WriteFile(pfxPath, []byte("this-is-not-a-valid-pfx"), 0o600); err != nil {
		t.Fatalf("write corrupt pfx: %v", err)
	}

	// Configure server: PFX is set but invalid; no PEM/ACME
	cfg := config.Load()
	cfg.TLSAutocertEnable = false
	cfg.TLSPFXFile = pfxPath
	cfg.TLSPFXPassword = "irrelevant"
	cfg.TLSCertFile = ""
	cfg.TLSKeyFile = ""
	cfg.HTTPSRedirect = false

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan struct{})
	go func() {
		_ = serveOnListener(ctx, ln, cfg, newLogger(slog.LevelError))
		close(done)
	}()

	// Give the server a moment to start
	time.Sleep(100 * time.Millisecond)

	// Client that accepts self-signed certs (test-only)
	url := fmt.Sprintf("https://%s/healthz", ln.Addr().String())
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		Timeout: 2 * time.Second,
	}

	// Expect 200 served via self-signed fallback
	resp, err := client.Get(url)
	if err != nil {
		t.Fatalf("GET /healthz (fallback): %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 via fallback, got %d", resp.StatusCode)
	}

	// Shutdown
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("server did not shut down in time")
	}
}

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

// ADD: helper to write a quick PEM cert+key pair to disk (self-signed)
func writeSelfSignedPEM(t *testing.T, cn string, hosts []string) (certPath, keyPath string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(9001),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     nil,
		IPAddresses:  nil,
	}
	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		} else {
			tmpl.DNSNames = append(tmpl.DNSNames, h)
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})

	dir := t.TempDir()
	certPath = filepath.Join(dir, "server.crt")
	keyPath = filepath.Join(dir, "server.key")
	if err := os.WriteFile(certPath, certPEM, 0o600); err != nil {
		t.Fatalf("write cert: %v", err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	return certPath, keyPath
}

// ADD: serveOnListener — PFX TLS happy path (HTTP redirect explicitly off)
func TestServeOnListener_PFXTLS_Healthz_NoRedirect(t *testing.T) {
	// Generate a modern PFX
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1111),
		Subject:      pkix.Name{CommonName: "pfx.local"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("cert: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	pfx, err := pkcs12modern.Modern.Encode(key, cert, nil, "pw")
	if err != nil {
		t.Fatalf("encode pfx: %v", err)
	}

	dir := t.TempDir()
	pfxPath := filepath.Join(dir, "server.pfx")
	if err := os.WriteFile(pfxPath, pfx, 0o600); err != nil {
		t.Fatalf("write pfx: %v", err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	cfg := config.Load()
	cfg.TLSAutocertEnable = false
	cfg.TLSPFXFile = pfxPath
	cfg.TLSPFXPassword = "pw"
	cfg.TLSCertFile, cfg.TLSKeyFile = "", ""
	// Force redirect OFF so we don't try to bind :80 during tests
	cfg.HTTPSRedirect = false
	cfg.HTTPSRedirectSet = true

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan struct{})
	go func() {
		_ = serveOnListener(ctx, ln, cfg, newLogger(slog.LevelError))
		close(done)
	}()

	time.Sleep(100 * time.Millisecond)

	url := fmt.Sprintf("https://%s/healthz", ln.Addr().String())
	client := &http.Client{
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}},
		Timeout:   2 * time.Second,
	}
	resp, err := client.Get(url)
	if err != nil {
		t.Fatalf("GET /healthz: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status: got %d, want %d", resp.StatusCode, http.StatusOK)
	}

	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("server did not shut down")
	}
}

// ADD: serveOnListener — PEM TLS happy path (HTTP redirect explicitly off)
func TestServeOnListener_PEMTLS_Healthz_NoRedirect(t *testing.T) {
	certPath, keyPath := writeSelfSignedPEM(t, "pem.local", []string{"localhost", "127.0.0.1"})

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	cfg := config.Load()
	cfg.TLSAutocertEnable = false
	cfg.TLSPFXFile = ""
	cfg.TLSPFXPassword = ""
	cfg.TLSCertFile = certPath
	cfg.TLSKeyFile = keyPath
	cfg.HTTPSRedirect = false
	cfg.HTTPSRedirectSet = true

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan struct{})
	go func() {
		_ = serveOnListener(ctx, ln, cfg, newLogger(slog.LevelError))
		close(done)
	}()

	time.Sleep(100 * time.Millisecond)

	url := fmt.Sprintf("https://%s/healthz", ln.Addr().String())
	client := &http.Client{
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}},
		Timeout:   2 * time.Second,
	}
	resp, err := client.Get(url)
	if err != nil {
		t.Fatalf("GET /healthz: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status: got %d, want %d", resp.StatusCode, http.StatusOK)
	}

	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("server did not shut down")
	}
}

// ADD: TLS1.3 server should reject TLS1.2-only client
func TestServeOnListener_TLS13_Rejects_TLS12_Client(t *testing.T) {
	// self-signed path is simplest
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	cfg := config.Load()
	cfg.TLSMinVersion = tls.VersionTLS13
	cfg.TLSAutocertEnable = false
	cfg.TLSPFXFile = ""
	cfg.TLSCertFile, cfg.TLSKeyFile = "", ""
	cfg.HTTPSRedirect = false
	cfg.HTTPSRedirectSet = true

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan struct{})
	go func() {
		_ = serveOnListener(ctx, ln, cfg, newLogger(slog.LevelError))
		close(done)
	}()

	time.Sleep(100 * time.Millisecond)

	url := fmt.Sprintf("https://%s/healthz", ln.Addr().String())
	// Force client to max out at TLS1.2
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
				MinVersion:         tls.VersionTLS12,
				MaxVersion:         tls.VersionTLS12,
			},
		},
		Timeout: 2 * time.Second,
	}
	if _, err := client.Get(url); err == nil {
		t.Fatal("expected handshake error for TLS1.2 client against TLS1.3-only server")
	}

	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("server did not shut down")
	}
}

// ADD: TLS1.2 server enforces specified cipher suite
func TestServeOnListener_TLS12_EnforcesCipher(t *testing.T) {
	// self-signed path is simplest
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	cfg := config.Load()
	cfg.TLSMinVersion = tls.VersionTLS12
	cfg.TLS12CipherSuites = []string{"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"}
	cfg.TLSAutocertEnable = false
	cfg.TLSPFXFile = ""
	cfg.TLSCertFile, cfg.TLSKeyFile = "", ""
	cfg.HTTPSRedirect = false
	cfg.HTTPSRedirectSet = true

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan struct{})
	go func() {
		_ = serveOnListener(ctx, ln, cfg, newLogger(slog.LevelError))
		close(done)
	}()

	time.Sleep(100 * time.Millisecond)

	// TLS1.2 client
	url := fmt.Sprintf("https://%s/healthz", ln.Addr().String())
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS12,
			MaxVersion:         tls.VersionTLS12,
		},
	}
	client := &http.Client{Transport: tr, Timeout: 2 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		t.Fatalf("GET /healthz: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status: got %d, want %d", resp.StatusCode, http.StatusOK)
	}
	if resp.TLS == nil {
		t.Fatal("no TLS connection state")
	}
	if resp.TLS.Version != tls.VersionTLS12 {
		t.Fatalf("tls version: got %x, want %x", resp.TLS.Version, tls.VersionTLS12)
	}
	if resp.TLS.CipherSuite != tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 {
		t.Fatalf("cipher: got %x, want %x", resp.TLS.CipherSuite, tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256)
	}

	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("server did not shut down")
	}
}

// ADD: when both PFX and PEM are configured, PFX should be used
func TestServeOnListener_BranchPreference_PFXOverPEM(t *testing.T) {
	// --- build a PFX cert with a distinctive CN ---
	pfxKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("pfx key: %v", err)
	}
	pfxTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(3001),
		Subject:      pkix.Name{CommonName: "pfx.local"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	pfxDER, err := x509.CreateCertificate(rand.Reader, pfxTmpl, pfxTmpl, &pfxKey.PublicKey, pfxKey)
	if err != nil {
		t.Fatalf("pfx cert: %v", err)
	}
	pfxCert, err := x509.ParseCertificate(pfxDER)
	if err != nil {
		t.Fatalf("pfx parse: %v", err)
	}
	pfxBytes, err := pkcs12modern.Modern.Encode(pfxKey, pfxCert, nil, "pw")
	if err != nil {
		t.Fatalf("pfx encode: %v", err)
	}

	// --- build a PEM cert with a different CN ---
	pemCertPath, pemKeyPath := writeSelfSignedPEM(t, "pem.local", []string{"localhost", "127.0.0.1"})

	// --- write PFX to disk ---
	dir := t.TempDir()
	pfxPath := filepath.Join(dir, "server.pfx")
	if err := os.WriteFile(pfxPath, pfxBytes, 0o600); err != nil {
		t.Fatalf("write pfx: %v", err)
	}

	// --- start server with BOTH PFX and PEM configured ---
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	cfg := config.Load()
	cfg.TLSAutocertEnable = false
	cfg.TLSPFXFile = pfxPath
	cfg.TLSPFXPassword = "pw"
	cfg.TLSCertFile = pemCertPath
	cfg.TLSKeyFile = pemKeyPath
	// Avoid binding :80 in CI
	cfg.HTTPSRedirect = false
	cfg.HTTPSRedirectSet = true

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan struct{})
	go func() {
		_ = serveOnListener(ctx, ln, cfg, newLogger(slog.LevelError))
		close(done)
	}()

	time.Sleep(100 * time.Millisecond)

	// --- connect and verify the served cert is the PFX cert (CN = pfx.local) ---
	url := fmt.Sprintf("https://%s/healthz", ln.Addr().String())
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		Timeout: 2 * time.Second,
	}
	resp, err := client.Get(url)
	if err != nil {
		t.Fatalf("GET /healthz: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status: got %d, want %d", resp.StatusCode, http.StatusOK)
	}
	if resp.TLS == nil || len(resp.TLS.PeerCertificates) == 0 {
		t.Fatal("expected peer certificates")
	}
	gotCN := resp.TLS.PeerCertificates[0].Subject.CommonName
	if gotCN != "pfx.local" {
		t.Fatalf("branch preference: got CN %q, want %q (PFX should win over PEM)", gotCN, "pfx.local")
	}

	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("server did not shut down")
	}
}
