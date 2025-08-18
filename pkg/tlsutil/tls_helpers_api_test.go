package tlsutil_test

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
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jsdraven/IT_Tools_GoLang/internal/entry"
	"github.com/jsdraven/IT_Tools_GoLang/pkg/config"
	"github.com/jsdraven/IT_Tools_GoLang/pkg/logging"
	"github.com/jsdraven/IT_Tools_GoLang/pkg/tlsutil"
	pkcs12modern "software.sslmate.com/src/go-pkcs12"
)

func TestResolveTLS12Suites(t *testing.T) {
	out := tlsutil.ResolveTLS12Suites([]string{
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
	if err := entry.Run(context.Background(), cfg); err != nil {
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

	c, err := tlsutil.LoadTLSFromPFX(p, "pass")
	if err != nil {
		t.Fatalf("tlsutil.LoadTLSFromPFX: %v", err)
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
	if _, err := tlsutil.LoadTLSFromPFX(p, "wrong"); err == nil {
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
	if _, err := tlsutil.LoadTLSFromPFX(p, "irrelevant"); err == nil {
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

	c, err := tlsutil.LoadTLSFromPFX(p, "pw")
	if err != nil {
		t.Fatalf("tlsutil.LoadTLSFromPFX(chain): %v", err)
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
		logger := logging.New(cfg)
		_ = entry.ServeOnListener(ctx, ln, cfg, logger)
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
	out := tlsutil.ResolveTLS12Suites([]string{
		"ECDHE-RSA-AES128-GCM-SHA256",
		"ecdhe-rsa-chacha20-poly1305",
		"INVALID",
	})
	if len(out) == 0 {
		t.Fatalf("expected some suites to resolve")
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
		logger := logging.New(cfg)
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
		logger := logging.New(cfg)
		_ = entry.ServeOnListener(ctx, ln, cfg, logger)
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

func TestGenerateSelfSigned(t *testing.T) {
	cert, err := tlsutil.GenerateSelfSigned()
	if err != nil {
		t.Fatalf("GenerateSelfSigned: %v", err)
	}
	if cert.Leaf == nil {
		t.Fatal("Leaf not parsed")
	}
	key, ok := cert.PrivateKey.(*rsa.PrivateKey)
	if !ok {
		t.Fatalf("PrivateKey type %T, want *rsa.PrivateKey", cert.PrivateKey)
	}
	if key.N.BitLen() != 2048 {
		t.Fatalf("key bit length = %d, want 2048", key.N.BitLen())
	}
	host, _ := os.Hostname()
	wantCN := "localhost"
	wantDNS := []string{"localhost"}
	if host != "" && host != "localhost" {
		wantCN = host
		wantDNS = append(wantDNS, host)
	}
	if cert.Leaf.Subject.CommonName != wantCN {
		t.Fatalf("CN = %q, want %q", cert.Leaf.Subject.CommonName, wantCN)
	}
	dnsSet := map[string]bool{}
	for _, d := range cert.Leaf.DNSNames {
		dnsSet[d] = true
	}
	for _, d := range wantDNS {
		if !dnsSet[d] {
			t.Fatalf("missing DNS SAN %q", d)
		}
	}
	wantIPs := map[string]bool{"127.0.0.1": false, "::1": false}
	for _, ip := range cert.Leaf.IPAddresses {
		if _, ok := wantIPs[ip.String()]; ok {
			wantIPs[ip.String()] = true
		}
	}
	for ip, seen := range wantIPs {
		if !seen {
			t.Fatalf("missing IP SAN %s", ip)
		}
	}
}
