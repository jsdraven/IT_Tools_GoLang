// Package config tests loading env configuration and level parsing.
// SPDX-License-Identifier: AGPL-3.0-or-later
package config_test

import (
	"log/slog"
	"testing"

	"github.com/jsdraven/IT_Tools_GoLang/pkg/config"
)

func TestLoadDefaults(t *testing.T) {
	t.Setenv("PORT", "")
	t.Setenv("LOG_LEVEL", "")
	cfg := config.Load()
	if got, want := cfg.Addr, ":8080"; got != want {
		t.Fatalf("Addr default: got %q, want %q", got, want)
	}
	if got, want := cfg.LogLevel, slog.LevelInfo; got != want {
		t.Fatalf("LogLevel default: got %v, want %v", got, want)
	}
}

func TestLoadOverrides(t *testing.T) {
	t.Setenv("PORT", "9090")
	t.Setenv("LOG_LEVEL", "DEBUG")
	cfg := config.Load()
	if got, want := cfg.Addr, ":9090"; got != want {
		t.Fatalf("Addr override: got %q, want %q", got, want)
	}
	if got, want := cfg.LogLevel, slog.LevelDebug; got != want {
		t.Fatalf("LogLevel override: got %v, want %v", got, want)
	}
}
