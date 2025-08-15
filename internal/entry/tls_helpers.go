// Package entry: tls_helpers contains all of the helpers for entry to properly handle TLS
package entry

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/jsdraven/IT_Tools_GoLang/internal/config"
	pkcs12modern "software.sslmate.com/src/go-pkcs12"
)

// resolveTLS12Suites maps names to Go cipher constants. Unknown names are ignored.
// If no names provided, returns nil and Go uses its secure defaults.
func resolveTLS12Suites(names []string) []uint16 {
	if len(names) == 0 {
		return nil
	}
	table := map[string]uint16{
		// Go constant names
		"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256": tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256":   tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		"TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384": tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384":   tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		"TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305":  tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
		"TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305":    tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
		// Common OpenSSL-style aliases
		"ECDHE-ECDSA-AES128-GCM-SHA256": tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		"ECDHE-RSA-AES128-GCM-SHA256":   tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		"ECDHE-ECDSA-AES256-GCM-SHA384": tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		"ECDHE-RSA-AES256-GCM-SHA384":   tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		"ECDHE-ECDSA-CHACHA20-POLY1305": tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
		"ECDHE-RSA-CHACHA20-POLY1305":   tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
	}
	var out []uint16
	for _, n := range names {
		key := strings.ToUpper(strings.TrimSpace(n))
		if v, ok := table[key]; ok {
			out = append(out, v)
		}
	}
	return out
}

// loadTLSFromPFX loads a PKCS#12 (.pfx/.p12) bundle and returns a tls.Certificate.
func loadTLSFromPFX(path, password string) (tls.Certificate, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return tls.Certificate{}, err
	}

	privKey, leaf, chain, err := pkcs12modern.DecodeChain(b, password)
	if err != nil {
		return tls.Certificate{}, err
	}

	certDER := make([][]byte, 0, 1+len(chain))
	certDER = append(certDER, leaf.Raw)
	for _, c := range chain {
		certDER = append(certDER, c.Raw)
	}

	return tls.Certificate{
		Certificate: certDER,
		PrivateKey:  privKey,
		Leaf:        leaf,
	}, nil
}

// generateSelfSigned creates an ephemeral RSA key and self-signed certificate
// with SANs for localhost/loopback and the machine hostname (if available).
func generateSelfSigned() (tls.Certificate, error) {
	// Key
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return tls.Certificate{}, err
	}

	// Subject + SANs
	cn := "localhost"
	dns := []string{"localhost"}
	ips := []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")}
	if host, err := os.Hostname(); err == nil && host != "" && host != "localhost" {
		dns = append(dns, host)
		cn = host
	}

	tmpl := &x509.Certificate{
		SerialNumber:          bigInt1(),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(90 * 24 * time.Hour), // ~90 days
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:              dns,
		IPAddresses:           ips,
		BasicConstraintsValid: true,
		SignatureAlgorithm:    x509.SHA256WithRSA,
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}

	// Encode to PEM and load as tls.Certificate (in-memory only)
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})

	c, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return tls.Certificate{}, err
	}
	if leaf, err := x509.ParseCertificate(der); err == nil {
		c.Leaf = leaf
	}
	return c, nil
}

// generateCSR writes a private key and CSR to TLSCSROutDir and returns nil on success.
func generateCSR(cfg *config.Config, logger *slog.Logger) error {
	if cfg.TLSCSROutDir == "" {
		cfg.TLSCSROutDir = "certs"
	}
	if err := os.MkdirAll(cfg.TLSCSROutDir, 0o700); err != nil {
		return err
	}

	// Key
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}
	keyPath := filepath.Join(cfg.TLSCSROutDir, "server.key")
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		return err
	}

	// CSR
	subj := pkix.Name{CommonName: cfg.TLSCSRCommonName}
	if cfg.TLSCSROrg != "" {
		subj.Organization = []string{cfg.TLSCSROrg}
	}
	var dnsSANs []string
	var ipSANs []net.IP
	for _, h := range cfg.TLSCSRHosts {
		h = strings.TrimSpace(h)
		if h == "" {
			continue
		}
		if ip := net.ParseIP(h); ip != nil {
			ipSANs = append(ipSANs, ip)
		} else {
			dnsSANs = append(dnsSANs, h)
		}
	}
	template := x509.CertificateRequest{
		Subject:            subj,
		DNSNames:           dnsSANs,
		IPAddresses:        ipSANs,
		SignatureAlgorithm: x509.SHA256WithRSA,
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &template, key)
	if err != nil {
		return err
	}
	csrPath := filepath.Join(cfg.TLSCSROutDir, "server.csr")
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})
	if err := os.WriteFile(csrPath, csrPEM, 0o600); err != nil {
		return err
	}

	// Log a short fingerprint for convenience
	sum := sha256SumHex(csrDER)
	logger.Info("csr_written", "key", keyPath, "csr", csrPath, "sha256", sum)
	return nil
}
