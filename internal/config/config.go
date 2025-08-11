// Package config loads application configuration from the envrionment veriables
// (supports a local .env file) and applies secure defaults
//
// SPDX-License-Identifier: AGPL-3.0-or-later
package config

import (
	"crypto/tls"
	"log/slog"
	"os"
	"strconv"
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

	// Security / CORS
	Env                string // dev|prod (affects some defaults later)
	HTTPSRedirect      bool   // if true, redirect HTTP -> HTTPS
	HSTSEnable         bool   // if true, set HSTS on HTTPS responses
	HSTSMaxAgeSeconds  int    // e.g., 63072000 (2 years)
	HSTSIncludeSubDom  bool
	HSTSPreload        bool     // keep false by default unless user opts in
	CORSAllowedOrigins []string // exact origins (comma-separated list in env)
	CORSAllowCreds     bool     // allow credentials for CORS responses
	CSPReportOnly      bool     // set CSP in Report-Only mode

	// Request/host hardening
	AllowedHosts []string // exact hostnames (comma-separated)
	MaxBodyBytes int64    // e.g., 1048576 (1 MiB). 0 => unlimited

	// TLS (self-termination)
	TLSCertFile   string
	TLSKeyFile    string
	TLSMinVersion uint16 // tls.VersionTLS13 or tls.VersionTLS12
}

func Load() *Config {
	// Load .env if present (ignored if missing)
	_ = godotenv.Load()

	port := getenvDefault("PORT", "8080")
	addr := ":" + port

	level := parseLevel(getenvDefault("LOG_LEVEL", "INFO"))

	// security-related defaults
	env := strings.ToLower(getenvDefault("ENV", "dev"))
	httpsRedirect := getenvBoolDefault("HTTPS_REDIRECT", false) // dev-friendly default
	hstsEnable := getenvBoolDefault("HSTS_ENABLE", false)       // off by default (safer for clones)
	hstsMaxAge := getenvIntDefault("HSTS_MAX_AGE", 0)           // set if HSTS_ENABLE=true
	hstsIncludeSub := getenvBoolDefault("HSTS_INCLUDE_SUBDOMAINS", false)
	hstsPreload := getenvBoolDefault("HSTS_PRELOAD", false)
	corsAllowed := splitCSV(getenvDefault("CORS_ALLOWED_ORIGINS", "")) // empty => same-origin only
	corsCreds := getenvBoolDefault("CORS_ALLOW_CREDENTIALS", false)    // default off
	cspReportOnly := getenvBoolDefault("CSP_REPORT_ONLY", false)
	allowedHosts := splitCSV(getenvDefault("ALLOWED_HOSTS", "")) // empty => any
	maxBodyBytes := getenvIntDefault("MAX_BODY_BYTES", 0)
	tlsCert := getenvDefault("TLS_CERT_FILE", "")
	tlsKey := getenvDefault("TLS_KEY_FILE", "")
	tlsMin := strings.TrimSpace(strings.ToUpper(getenvDefault("TLS_MIN_VERSION", "TLS1.3")))
	var tlsMinVer uint16 = tls.VersionTLS13
	if tlsMin == "TLS1.2" {
		tlsMinVer = tls.VersionTLS12
	}
	return &Config{
		Addr:               addr,
		LogLevel:           level,
		ReadHeaderTimeout:  5 * time.Second,
		ReadTimeout:        10 * time.Second,
		WriteTimeout:       10 * time.Second,
		IdleTimeout:        60 * time.Second,
		Env:                env,
		HTTPSRedirect:      httpsRedirect,
		HSTSEnable:         hstsEnable,
		HSTSMaxAgeSeconds:  hstsMaxAge,
		HSTSIncludeSubDom:  hstsIncludeSub,
		HSTSPreload:        hstsPreload,
		CORSAllowedOrigins: corsAllowed,
		CORSAllowCreds:     corsCreds,
		CSPReportOnly:      cspReportOnly,
		AllowedHosts:       allowedHosts,
		MaxBodyBytes:       int64(maxBodyBytes),
		TLSCertFile:        tlsCert,
		TLSKeyFile:         tlsKey,
		TLSMinVersion:      tlsMinVer,
	}
}

func getenvDefault(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func getenvBoolDefault(k string, def bool) bool {
	v := strings.ToLower(strings.TrimSpace(os.Getenv(k)))
	if v == "" {
		return def
	}
	switch v {
	case "1", "true", "yes", "on":
		return true
	case "0", "false", "no", "off":
		return false
	default:
		return def
	}
}

func getenvIntDefault(k string, def int) int {
	v := strings.TrimSpace(os.Getenv(k))
	if v == "" {
		return def
	}
	if n, err := strconv.Atoi(v); err == nil {
		return n
	}
	return def
}

func splitCSV(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
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
