// Package main is the entrypoint for the IT_Tools_GoLang HTTP server.
// SPDX-License-Identifier: AGPL-3.0-or-later
package main

import (
	"context"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"time"

	"github.com/jsdraven/IT_Tools_GoLang/internal/config"
	"github.com/jsdraven/IT_Tools_GoLang/internal/server"
)

// serveOnListener runs the HTTP server until ctx is cancelled.
// It logs start/stop, applies secure timeouts, and shuts down gracefully.
func serveOnListener(ctx context.Context, ln net.Listener, cfg *config.Config, logger *slog.Logger) error {
	srv := &http.Server{
		Handler:           server.NewRouter(logger),
		ReadHeaderTimeout: cfg.ReadHeaderTimeout,
		ReadTimeout:       cfg.ReadTimeout,
		WriteTimeout:      cfg.WriteTimeout,
		IdleTimeout:       cfg.IdleTimeout,
	}

	logger.Info("server_listening", "addr", ln.Addr().String())
	go func() {
		// Serve will return http.ErrServerClosed on graceful shutdown.
		if err := srv.Serve(ln); err != nil && err != http.ErrServerClosed {
			logger.Error("server_error", "err", err)
		}
	}()

	// Wait for cancellation, then shut down.
	<-ctx.Done()
	ctxShut, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = srv.Shutdown(ctxShut)
	logger.Info("server_stopped")
	return nil
}

func main() {
	// Load configuration and logger
	cfg := config.Load()
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: cfg.LogLevel,
	}))

	// Bind listener (supports ":8080" or "127.0.0.1:0" for ephemeral)
	ln, err := net.Listen("tcp", cfg.Addr)
	if err != nil {
		logger.Error("listen_error", "err", err, "addr", cfg.Addr)
		os.Exit(1)
	}
	defer ln.Close()

	// Stop on Ctrl+C
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	if err := serveOnListener(ctx, ln, cfg, logger); err != nil && err != http.ErrServerClosed {
		logger.Error("fatal_server_error", "err", err)
		os.Exit(1)
	}
}
