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

func TestServeOnListener_ServesHealthz(t *testing.T) {
	// Configure ephemeral port via listener
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	// Minimal config with defaults (timeouts, etc.)
	t.Setenv("PORT", "0") // not used when we pass ln explicitly
	t.Setenv("LOG_LEVEL", "ERROR")
	cfg := config.Load()

	// Run server until context cancelled
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() { errCh <- serveOnListener(ctx, ln, cfg, discardLogger()) }()

	// Give it a brief moment to start
	time.Sleep(50 * time.Millisecond)

	// Hit /healthz and expect 200
	url := "http://" + ln.Addr().String() + "/healthz"
	resp, err := http.Get(url)
	if err != nil {
		t.Fatalf("GET /healthz: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status: got %d, want %d", resp.StatusCode, http.StatusOK)
	}

	// Stop the server
	cancel()
	select {
	case <-time.After(1 * time.Second):
		t.Fatal("server did not stop in time")
	case <-errCh:
		// ok (serveOnListener returns nil after graceful shutdown)
	}
}
