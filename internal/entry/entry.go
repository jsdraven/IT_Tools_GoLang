// Package entry exposes the entrypoint helpers used by main().
// SPDX-License-Identifier: AGPL-3.0-or-later
package entry

import (
	"context"
	"crypto/tls"
	"log/slog"
	"net"
	"net/http"
	"time"

	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"

	"github.com/jsdraven/IT_Tools_GoLang/internal/server"
	"github.com/jsdraven/IT_Tools_GoLang/pkg/config"
	"github.com/jsdraven/IT_Tools_GoLang/pkg/logging"
	"github.com/jsdraven/IT_Tools_GoLang/pkg/tlsutil"
)

// BindListener binds a TCP listener and logs failures.
func BindListener(addr string, logger *slog.Logger) (net.Listener, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		logger.Error("listen_error", "err", err, "addr", addr)
		return nil, err
	}
	return ln, nil
}

// Run wires config, logger, listener, and serving loop together.
// If TLSGenerateCSR=true, it writes a key+CSR and exits without starting the server.
func Run(ctx context.Context, cfg *config.Config) error {
	logger := logging.New(cfg)

	// Optional CSR generation mode
	if cfg.TLSGenerateCSR {
		if err := tlsutil.GenerateCSR(cfg, logger); err != nil {
			return err
		}
		logger.Info("csr_generated", "out_dir", cfg.TLSCSROutDir)
		return nil
	}

	ln, err := BindListener(cfg.Addr, logger)
	if err != nil {
		return err
	}
	defer ln.Close()

	return ServeOnListener(ctx, ln, cfg, logger)
}

// ServeOnListener runs the HTTP server until ctx is cancelled.
func ServeOnListener(ctx context.Context, ln net.Listener, cfg *config.Config, logger *slog.Logger) error {
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
				var fallback http.Handler
				if wantHTTPRedirect(cfg, false /* real cert */) {
					fallback = redirectToHTTPSHandler(cfg.Addr)
				}
				if err := http.ListenAndServe(":80", m.HTTPHandler(fallback)); err != nil {
					logger.Warn("acme_http_01_bind_failed", "err", err)
				}
			}()

			// Compose TLS config
			base := &tls.Config{
				MinVersion: cfg.TLSMinVersion,
			}
			if cfg.TLSMinVersion == tls.VersionTLS12 {
				base.CipherSuites = tlsutil.ResolveTLS12Suites(cfg.TLS12CipherSuites)
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
			if wantHTTPRedirect(cfg, false /* real cert */) {
				go func() {
					if err := http.ListenAndServe(":80", redirectToHTTPSHandler(cfg.Addr)); err != nil {
						logger.Warn("http_redirect_bind_failed", "err", err)
					}
				}()
			}
			cert, err := tlsutil.LoadTLSFromPFX(cfg.TLSPFXFile, cfg.TLSPFXPassword)
			if err != nil {
				logger.Error("pfx_load_failed", "err", err)
			} else {
				tlsCfg := &tls.Config{
					MinVersion:   cfg.TLSMinVersion,
					Certificates: []tls.Certificate{cert},
				}
				if cfg.TLSMinVersion == tls.VersionTLS12 {
					tlsCfg.CipherSuites = tlsutil.ResolveTLS12Suites(cfg.TLS12CipherSuites)
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
			if wantHTTPRedirect(cfg, false /* real cert */) {
				go func() {
					if err := http.ListenAndServe(":80", redirectToHTTPSHandler(cfg.Addr)); err != nil {
						logger.Warn("http_redirect_bind_failed", "err", err)
					}
				}()
			}
			srv.TLSConfig = &tls.Config{
				MinVersion: cfg.TLSMinVersion,
			}
			if cfg.TLSMinVersion == tls.VersionTLS12 {
				srv.TLSConfig.CipherSuites = tlsutil.ResolveTLS12Suites(cfg.TLS12CipherSuites)
			}
			if err := srv.ServeTLS(ln, cfg.TLSCertFile, cfg.TLSKeyFile); err != nil && err != http.ErrServerClosed {
				logger.Error("server_error", "err", err)
			}
			return
		}

		// 4) Self-signed TLS (default when nothing else is configured)
		// Generates an ephemeral certificate at startup for quick, safer-by-default HTTPS.
		{
			cert, err := tlsutil.GenerateSelfSigned()
			if err != nil {
				logger.Error("selfsigned_generate_failed", "err", err)
				// Fallback to plain HTTP only if self-signed generation fails.
				if err := srv.Serve(ln); err != nil && err != http.ErrServerClosed {
					logger.Error("server_error", "err", err)
				}
				return
			}
			if wantHTTPRedirect(cfg, true /* self-signed */) {
				go func() {
					if err := http.ListenAndServe(":80", redirectToHTTPSHandler(cfg.Addr)); err != nil {
						logger.Warn("http_redirect_bind_failed", "err", err)
					}
				}()
			}
			tlsCfg := &tls.Config{
				MinVersion:   cfg.TLSMinVersion,
				Certificates: []tls.Certificate{cert},
			}
			if cfg.TLSMinVersion == tls.VersionTLS12 {
				tlsCfg.CipherSuites = tlsutil.ResolveTLS12Suites(cfg.TLS12CipherSuites)
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
