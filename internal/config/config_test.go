// Package config tests loading env configuration and level parsing.
// SPDX-License-Identifier: AGPL-3.0-or-later
package config

import (
	"log/slog"
	"testing"
)

func TestLoadDefaults(t *testing.T) {
	t.Setenv("PORT", "")
	t.Setenv("LOG_LEVEL", "")
	cfg := Load()
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
	cfg := Load()
	if got, want := cfg.Addr, ":9090"; got != want {
		t.Fatalf("Addr override: got %q, want %q", got, want)
	}
	if got, want := cfg.LogLevel, slog.LevelDebug; got != want {
		t.Fatalf("LogLevel override: got %v, want %v", got, want)
	}
}

func TestParseLevelTable(t *testing.T) {
	cases := []struct {
		in   string
		want slog.Level
	}{
		{"DEBUG", slog.LevelDebug},
		{"Warn", slog.LevelWarn},
		{"error", slog.LevelError},
		{"INFO", slog.LevelInfo}, // explicit
		{"", slog.LevelInfo},     // default on empty/unknown
		{"nope", slog.LevelInfo}, // default on unknown
	}
	for _, tc := range cases {
		if got := parseLevel(tc.in); got != tc.want {
			t.Fatalf("parseLevel(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}
