// Package main exposes the entrypoint helpers used by main().
// SPDX-License-Identifier: AGPL-3.0-or-later
package main

import (
	"context"
	"crypto/tls"
	"log/slog"
	"net"
	"net/http"
	"os"
	"time"

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

// serveOnListener runs the HTTP server until ctx is cancelled.
func serveOnListener(ctx context.Context, ln net.Listener, cfg *config.Config, logger *slog.Logger) error {
	srv := &http.Server{
		Handler:           server.NewRouter(cfg, logger), // <-- important: pass cfg, logger
		ReadHeaderTimeout: cfg.ReadHeaderTimeout,
		ReadTimeout:       cfg.ReadTimeout,
		WriteTimeout:      cfg.WriteTimeout,
		IdleTimeout:       cfg.IdleTimeout,
	}

	logger.Info("server_listening", "addr", ln.Addr().String())

	go func() {
		// Wrap listener with TLS if cert/key provided
		if cfg.TLSCertFile != "" && cfg.TLSKeyFile != "" {
			tlsCfg := &tls.Config{MinVersion: cfg.TLSMinVersion}
			ln = tls.NewListener(ln, tlsCfg)
			if err := srv.ServeTLS(ln, cfg.TLSCertFile, cfg.TLSKeyFile); err != nil && err != http.ErrServerClosed {
				logger.Error("server_error", "err", err)
			}
			return
		}
		if err := srv.Serve(ln); err != nil && err != http.ErrServerClosed {
			logger.Error("server_error", "err", err)
		}
	}()

	<-ctx.Done()
	ctxShut, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = srv.Shutdown(ctxShut)
	logger.Info("server_stopped")
	return nil
}

// run wires config, logger, listener, and serving loop together.
func run(ctx context.Context, cfg *config.Config) error {
	logger := newLogger(cfg.LogLevel)
	ln, err := bindListener(cfg.Addr, logger)
	if err != nil {
		return err
	}
	defer ln.Close()
	return serveOnListener(ctx, ln, cfg, logger)
}
