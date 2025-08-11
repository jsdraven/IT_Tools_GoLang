// Package main tests the entrypoint helpers for booting the HTTP server.
// SPDX-License-Identifier: AGPL-3.0-or-later
package main

import (
	"context"
	"io"
	"log/slog"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/jsdraven/IT_Tools_GoLang/internal/config"
)

func discardLogger() *slog.Logger {
	return slog.New(slog.NewJSONHandler(io.Discard, nil))
}

func TestStartServer_ServesHealthz(t *testing.T) {
	t.Setenv("PORT", "0") // ask OS for an ephemeral port
	t.Setenv("LOG_LEVEL", "ERROR")
	cfg := config.Load()
	logger := discardLogger()

	srv := startServer(cfg, logger)

	// Bind a listener ourselves so we can discover the chosen port.
	ln, err := net.Listen("tcp", cfg.Addr)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	// Serve in the background.
	srvErr := make(chan error, 1)
	go func() {
		srvErr <- srv.Serve(ln)
	}()

	// Build base URL from the actual listener address.
	url := "http://" + ln.Addr().String()

	// Give the server a brief moment to start accepting.
	time.Sleep(50 * time.Millisecond)

	// Hit /healthz and expect 200 ok.
	resp, err := http.Get(url + "/healthz")
	if err != nil {
		t.Fatalf("GET /healthz: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status: got %d, want %d", resp.StatusCode, http.StatusOK)
	}

	// Shutdown cleanly.
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		t.Fatalf("shutdown: %v", err)
	}

	// Allow Serve to exit.
	select {
	case err := <-srvErr:
		if err != http.ErrServerClosed && err != nil {
			t.Fatalf("serve error: %v", err)
		}
	case <-time.After(1 * time.Second):
		t.Fatal("server did not stop in time")
	}
}
