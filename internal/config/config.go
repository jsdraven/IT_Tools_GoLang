// Package config loads application configuration from the envrionment veriables
// (supports a local .env file) and applies secure defaults
//
// SPDX-License-Identifier: AGPL-3.0-or-later
package config

import (
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/joho/godotenv"
)

type Config struct {
	Addr              string
	LogLevel          slog.Level
	ReadHeaderTimeout time.Duration
	ReadTimeout       time.Duration
	WriteTimeout      time.Duration
	IdleTimeout       time.Duration
}

func Load() *Config {
	// Load .env if present (ignored if missing)
	_ = godotenv.Load()

	port := getenvDefault("PORT", "8080")
	addr := ":" + port

	level := parseLevel(getenvDefault("LOG_LEVEL", "INFO"))

	return &Config{
		Addr:              addr,
		LogLevel:          level,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
}

func getenvDefault(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func parseLevel(s string) slog.Level {
	switch strings.ToUpper(s) {
	case "DEBUG":
		return slog.LevelDebug
	case "WARN":
		return slog.LevelWarn
	case "ERROR":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}
