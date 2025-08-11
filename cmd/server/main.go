// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Package main is the entrypoint for the IT_Tools_GoLang HTTP Server
package main

import (
	"context"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"time"

	"github.com/jsdraven/IT_Tools_GoLang/internal/config"
	"github.com/jsdraven/IT_Tools_GoLang/internal/server"
)

func main() {
	// Load configuration from env + defaults
	cfg := config.Load()

	// Structured JSON logger with level from config
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: cfg.LogLevel,
	}))

	// Build router and HTTP server with security-focused timeouts
	handler := server.NewRouter(logger)
	srv := &http.Server{
		Addr:              cfg.Addr,
		Handler:           handler,
		ReadHeaderTimeout: cfg.ReadHeaderTimeout,
		ReadTimeout:       cfg.ReadTimeout,
		WriteTimeout:      cfg.WriteTimeout,
		IdleTimeout:       cfg.IdleTimeout,
	}

	// Start server
	go func() {
		logger.Info("server_listening", "addr", cfg.Addr)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Error("server_error", "err", err)
			os.Exit(1)
		}
	}()

	// Graceful shutdown on Ctrl+C
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt)
	<-stop

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		logger.Error("graceful_shutdown_failed", "err", err)
	} else {
		logger.Info("server_stopped")
	}
}
