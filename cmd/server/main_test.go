// Package main tests the entrypoint helpers for booting the HTTP server.
// SPDX-License-Identifier: AGPL-3.0-or-later
package main

import (
	"context"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/jsdraven/IT_Tools_GoLang/internal/config"
)

func discardLogger() *slog.Logger {
	return slog.New(slog.NewJSONHandler(io.Discard, nil))
}

func TestNewLogger(t *testing.T) {
	t.Helper()
	l := newLogger(slog.LevelInfo)
	if l == nil {
		t.Fatal("expected non-nil logger")
	}
}

func TestBindListener_Invalid(t *testing.T) {
	t.Helper()
	// 65536 is an invalid TCP port, should error
	_, err := bindListener("127.0.0.1:65536", discardLogger())
	if err == nil {
		t.Fatal("expected error for invalid port, got nil")
	}
}

func TestBindListener_Ephemeral(t *testing.T) {
	logger := discardLogger()
	ln, err := bindListener("127.0.0.1:0", logger)
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
	go func() { done <- run(ctx, cfg) }()

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

	if err := run(ctx, cfg); err == nil {
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
	go func() { errCh <- serveOnListener(ctx, ln, cfg, discardLogger()) }()

	time.Sleep(50 * time.Millisecond) // brief startup window
	base := "http://" + ln.Addr().String()

	// /healthz should return 200
	if resp, err := http.Get(base + "/healthz"); err != nil {
		t.Fatalf("GET /healthz: %v", err)
	} else {
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status /healthz: got %d", resp.StatusCode)
		}
	}

	// / should return 200
	if resp, err := http.Get(base + "/"); err != nil {
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
