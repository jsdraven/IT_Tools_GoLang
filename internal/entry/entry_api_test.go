package entry_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jsdraven/IT_Tools_GoLang/internal/config"
	"github.com/jsdraven/IT_Tools_GoLang/internal/entry"
	"github.com/jsdraven/IT_Tools_GoLang/internal/log"
	pkcs12modern "software.sslmate.com/src/go-pkcs12"
)

func discardLogger() *slog.Logger {
	return slog.New(slog.NewJSONHandler(io.Discard, nil))
}

func TestBindListener_Invalid(t *testing.T) {
	t.Helper()
	// 65536 is an invalid TCP port, should error
	_, err := entry.BindListener("127.0.0.1:65536", discardLogger())
	if err == nil {
		t.Fatal("expected error for invalid port, got nil")
	}
}

func TestBindListener_Ephemeral(t *testing.T) {
	logger := discardLogger()
	ln, err := entry.BindListener("127.0.0.1:0", logger)
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
	go func() { done <- entry.Run(ctx, cfg) }()

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

	if err := entry.Run(ctx, cfg); err == nil {
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
	go func() { errCh <- entry.ServeOnListener(ctx, ln, cfg, discardLogger()) }()

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
		logger := log.New(cfg)
		_ = entry.ServeOnListener(ctx, ln, cfg, logger)
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
		logger := log.New(cfg)
		_ = entry.ServeOnListener(ctx, ln, cfg, logger)
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
		logger := log.New(cfg)
		_ = entry.ServeOnListener(ctx, ln, cfg, logger)
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
		logger := log.New(cfg)
		_ = entry.ServeOnListener(ctx, ln, cfg, logger)
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
		logger := log.New(cfg)
		_ = entry.ServeOnListener(ctx, ln, cfg, logger)
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
