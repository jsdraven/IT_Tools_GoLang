// Package main exposes the entrypoint helpers used by main().
// SPDX-License-Identifier: AGPL-3.0-or-later
package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
	pkcs12modern "software.sslmate.com/src/go-pkcs12"

	"github.com/jsdraven/IT_Tools_GoLang/internal/config"
	"github.com/jsdraven/IT_Tools_GoLang/internal/server"
)

// newLogger constructs a JSON slog logger at the desired level.
func newLogger(level slog.Level) *slog.Logger {
	return slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: level}))
}

// bindListener binds a TCP listener and logs failures.
func bindListener(addr string, logger *slog.Logger) (net.Listener, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		logger.Error("listen_error", "err", err, "addr", addr)
		return nil, err
	}
	return ln, nil
}

// run wires config, logger, listener, and serving loop together.
// If TLSGenerateCSR=true, it writes a key+CSR and exits without starting the server.
func run(ctx context.Context, cfg *config.Config) error {
	logger := newLogger(cfg.LogLevel)

	// Optional CSR generation mode
	if cfg.TLSGenerateCSR {
		if err := generateCSR(cfg, logger); err != nil {
			return err
		}
		logger.Info("csr_generated", "out_dir", cfg.TLSCSROutDir)
		return nil
	}

	ln, err := bindListener(cfg.Addr, logger)
	if err != nil {
		return err
	}
	defer ln.Close()

	return serveOnListener(ctx, ln, cfg, logger)
}

// serveOnListener runs the HTTP server until ctx is cancelled.
func serveOnListener(ctx context.Context, ln net.Listener, cfg *config.Config, logger *slog.Logger) error {
	srv := &http.Server{
		Handler:           server.NewRouter(cfg, logger),
		ReadHeaderTimeout: cfg.ReadHeaderTimeout,
		ReadTimeout:       cfg.ReadTimeout,
		WriteTimeout:      cfg.WriteTimeout,
		IdleTimeout:       cfg.IdleTimeout,
	}

	logger.Info("server_listening", "addr", ln.Addr().String())

	go func() {
		// 1) ACME (Let's Encrypt) via autocert
		if cfg.TLSAutocertEnable && len(cfg.TLSAutocertHosts) > 0 {
			m := &autocert.Manager{
				Prompt:     autocert.AcceptTOS,
				Cache:      autocert.DirCache(cfg.TLSAutocertCacheDir),
				HostPolicy: autocert.HostWhitelist(cfg.TLSAutocertHosts...),
				Email:      cfg.TLSAutocertEmail,
			}
			if cfg.TLSACMEDirectoryURL != "" {
				m.Client = &acme.Client{DirectoryURL: cfg.TLSACMEDirectoryURL}
			}

			// Challenge server on :80 (required for HTTP-01). If bind fails, log and continue.
			go func() {
				if err := http.ListenAndServe(":80", m.HTTPHandler(nil)); err != nil {
					logger.Warn("acme_http_01_bind_failed", "err", err)
				}
			}()

			// Compose TLS config
			base := &tls.Config{
				MinVersion: cfg.TLSMinVersion,
			}
			if cfg.TLSMinVersion == tls.VersionTLS12 {
				base.CipherSuites = resolveTLS12Suites(cfg.TLS12CipherSuites)
			}
			ac := m.TLSConfig()
			// Merge base restrictions into autocert config
			ac.MinVersion = base.MinVersion
			if len(base.CipherSuites) > 0 {
				ac.CipherSuites = base.CipherSuites
			}

			tlsLn := tls.NewListener(ln, ac)
			if err := srv.Serve(tlsLn); err != nil && err != http.ErrServerClosed {
				logger.Error("server_error", "err", err)
			}
			return
		}

		// 2) PFX/PKCS#12 (e.g., AD CS)
		if cfg.TLSPFXFile != "" {
			cert, err := loadTLSFromPFX(cfg.TLSPFXFile, cfg.TLSPFXPassword)
			if err != nil {
				logger.Error("pfx_load_failed", "err", err)
			} else {
				tlsCfg := &tls.Config{
					MinVersion:   cfg.TLSMinVersion,
					Certificates: []tls.Certificate{cert},
				}
				if cfg.TLSMinVersion == tls.VersionTLS12 {
					tlsCfg.CipherSuites = resolveTLS12Suites(cfg.TLS12CipherSuites)
				}
				tlsLn := tls.NewListener(ln, tlsCfg)
				if err := srv.Serve(tlsLn); err != nil && err != http.ErrServerClosed {
					logger.Error("server_error", "err", err)
				}
				return
			}
		}

		// 3) PEM cert/key pair
		if cfg.TLSCertFile != "" && cfg.TLSKeyFile != "" {
			// Note: ServeTLS will read the files; we still enforce min/ciphers via Server.TLSConfig
			srv.TLSConfig = &tls.Config{
				MinVersion: cfg.TLSMinVersion,
			}
			if cfg.TLSMinVersion == tls.VersionTLS12 {
				srv.TLSConfig.CipherSuites = resolveTLS12Suites(cfg.TLS12CipherSuites)
			}
			if err := srv.ServeTLS(ln, cfg.TLSCertFile, cfg.TLSKeyFile); err != nil && err != http.ErrServerClosed {
				logger.Error("server_error", "err", err)
			}
			return
		}

		// 4) Self-signed TLS (default when nothing else is configured)
		// Generates an ephemeral certificate at startup for quick, safer-by-default HTTPS.
		{
			cert, err := generateSelfSigned()
			if err != nil {
				logger.Error("selfsigned_generate_failed", "err", err)
				// Fallback to plain HTTP only if self-signed generation fails.
				if err := srv.Serve(ln); err != nil && err != http.ErrServerClosed {
					logger.Error("server_error", "err", err)
				}
				return
			}
			tlsCfg := &tls.Config{
				MinVersion:   cfg.TLSMinVersion,
				Certificates: []tls.Certificate{cert},
			}
			if cfg.TLSMinVersion == tls.VersionTLS12 {
				tlsCfg.CipherSuites = resolveTLS12Suites(cfg.TLS12CipherSuites)
			}
			logger.Warn("using_self_signed_tls", "note", "for staging/dev; configure ACME/PFX/PEM for production")
			tlsLn := tls.NewListener(ln, tlsCfg)
			if err := srv.Serve(tlsLn); err != nil && err != http.ErrServerClosed {
				logger.Error("server_error", "err", err)
			}
		}
	}()

	<-ctx.Done()
	ctxShut, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = srv.Shutdown(ctxShut)
	logger.Info("server_stopped")
	return nil
}

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

func sha256SumHex(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:16]) // 128-bit prefix
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

// bigInt1 returns a constant serial number for simplicity.
func bigInt1() *big.Int { return big.NewInt(1) }
