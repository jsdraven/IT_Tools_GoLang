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

	// Logging hygiene
	LogIncludeQuery   bool     // include ?query in request logs (default: false)
	LogAllowedHeaders []string // explicit allowlist of headers to log (comma-separated env)
	LogRedactHeaders  []string // headers whose values are redacted if present
	LogHashIPs        bool     // hash/anonymize remote IP in logs
	LogIPHashSalt     string   // optional salt used when hashing IPs
	LogSkipPaths      []string // path prefixes to skip logging entirely (e.g., /healthz)

	// Rate-limit / ban
	RateLimitRPS         int  // requests per second per IP
	RateLimitBurst       int  // token bucket burst
	BanThreshold         int  // 429 hits before ban
	BanWindowSeconds     int  // window for counting 429 hits
	BanDurationSeconds   int  // ban length
	TrustProxy           bool // use X-Forwarded-For first hop
	BanSilentDrop        bool // attempt to drop connection (no reply) when banned
	AdminEndpointsEnable bool // expose read-only /admin/bans

	// Request/host hardening
	AllowedHosts []string // exact hostnames (comma-separated)
	MaxBodyBytes int64    // e.g., 1048576 (1 MiB). 0 => unlimited

	// TLS (self-termination)
	TLSCertFile   string
	TLSKeyFile    string
	TLSMinVersion uint16 // tls.VersionTLS13 or tls.VersionTLS12

	// TLS ACME (Let's Encrypt) automation
	TLSAutocertEnable   bool     // enable autocert manager
	TLSAutocertEmail    string   // registration/notification email
	TLSAutocertHosts    []string // allowed hostnames for certificates
	TLSAutocertCacheDir string   // directory to cache certs
	TLSACMEDirectoryURL string   // optional directory URL (e.g., LE staging/prod)

	// TLS PFX/PKCS#12 support (e.g., from AD CS)
	TLSPFXFile     string // path to .pfx/.p12 bundle
	TLSPFXPassword string // password for PFX

	// TLS (advanced)
	TLS12CipherSuites []string // names of TLS1.2 cipher suites to allow (empty => secure default)

	// CSR generation (manual issuance flow)
	TLSGenerateCSR   bool     // when true, generate a CSR and private key at startup then exit
	TLSCSRCommonName string   // CN for CSR
	TLSCSRHosts      []string // DNS/IP SANs (comma-separated)
	TLSCSROrg        string   // organization name
	TLSCSROutDir     string   // where to write key+csr (e.g., ./certs)
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

	// Logging hygiene
	logIncludeQuery := getenvBoolDefault("LOG_INCLUDE_QUERY", false)
	logAllowedHeaders := splitCSV(getenvDefault("LOG_ALLOWED_HEADERS", "")) // none by default
	logRedactHeaders := splitCSV(getenvDefault("LOG_REDACT_HEADERS", "Authorization, Cookie"))
	logHashIPs := getenvBoolDefault("LOG_HASH_IPS", false)
	logIPHashSalt := getenvDefault("LOG_IP_HASH_SALT", "")
	logSkipPaths := splitCSV(getenvDefault("LOG_SKIP_PATHS", "/healthz"))

	// Rate-limit / ban defaults
	rlRPS := getenvIntDefault("RATE_LIMIT_RPS", 5)
	rlBurst := getenvIntDefault("RATE_LIMIT_BURST", 10)
	banThresh := getenvIntDefault("BAN_THRESHOLD", 5)
	banWindow := getenvIntDefault("BAN_WINDOW_SECONDS", 60)
	banDuration := getenvIntDefault("BAN_DURATION_SECONDS", 900) // 15m
	trustProxy := getenvBoolDefault("TRUST_PROXY", false)
	banSilent := getenvBoolDefault("BAN_SILENT_DROP", false)
	adminEnable := getenvBoolDefault("ADMIN_ENDPOINTS_ENABLE", false)

	// Request/host hardening
	allowedHosts := splitCSV(getenvDefault("ALLOWED_HOSTS", "")) // empty => any
	maxBodyBytes := getenvIntDefault("MAX_BODY_BYTES", 0)

	// TLS (self-termination)
	tlsCert := getenvDefault("TLS_CERT_FILE", "")
	tlsKey := getenvDefault("TLS_KEY_FILE", "")
	tlsMin := strings.TrimSpace(strings.ToUpper(getenvDefault("TLS_MIN_VERSION", "TLS1.3")))
	var tlsMinVer uint16 = tls.VersionTLS13
	if tlsMin == "TLS1.2" {
		tlsMinVer = tls.VersionTLS12
	}

	// TLS ACME (Let's Encrypt)
	acmeEnable := getenvBoolDefault("TLS_AUTOCERT_ENABLE", false)
	acmeEmail := getenvDefault("TLS_AUTOCERT_EMAIL", "")
	acmeHosts := splitCSV(getenvDefault("TLS_AUTOCERT_HOSTS", ""))
	acmeCache := getenvDefault("TLS_AUTOCERT_CACHE_DIR", "acme-cache")
	acmeDirURL := getenvDefault("TLS_ACME_DIRECTORY_URL", "")

	// TLS PFX/PKCS#12
	pfxFile := getenvDefault("TLS_PFX_FILE", "")
	pfxPass := getenvDefault("TLS_PFX_PASSWORD", "")

	// TLS (advanced)
	tls12Suites := splitCSV(getenvDefault("TLS12_CIPHER_SUITES", "")) // names; resolved later

	// CSR generation (manual issuance)
	genCSR := getenvBoolDefault("TLS_GENERATE_CSR", false)
	csrCN := getenvDefault("TLS_CSR_CN", "")
	csrHosts := splitCSV(getenvDefault("TLS_CSR_HOSTS", ""))
	csrOrg := getenvDefault("TLS_CSR_ORG", "")
	csrOut := getenvDefault("TLS_CSR_OUT_DIR", "certs")

	return &Config{
		Addr:              addr,
		LogLevel:          level,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
		Env:               env,
		// security-related defaults
		HTTPSRedirect:      httpsRedirect,
		HSTSEnable:         hstsEnable,
		HSTSMaxAgeSeconds:  hstsMaxAge,
		HSTSIncludeSubDom:  hstsIncludeSub,
		HSTSPreload:        hstsPreload,
		CORSAllowedOrigins: corsAllowed,
		CORSAllowCreds:     corsCreds,
		CSPReportOnly:      cspReportOnly,
		// Logging hygiene
		LogIncludeQuery:   logIncludeQuery,
		LogAllowedHeaders: logAllowedHeaders,
		LogRedactHeaders:  logRedactHeaders,
		LogHashIPs:        logHashIPs,
		LogIPHashSalt:     logIPHashSalt,
		LogSkipPaths:      logSkipPaths,
		// Rate-limit / ban defaults
		RateLimitRPS:         rlRPS,
		RateLimitBurst:       rlBurst,
		BanThreshold:         banThresh,
		BanWindowSeconds:     banWindow,
		BanDurationSeconds:   banDuration,
		TrustProxy:           trustProxy,
		BanSilentDrop:        banSilent,
		AdminEndpointsEnable: adminEnable,

		// Request/host hardening
		AllowedHosts: allowedHosts,
		MaxBodyBytes: int64(maxBodyBytes),

		// TLS (self-termination)
		TLSCertFile:   tlsCert,
		TLSKeyFile:    tlsKey,
		TLSMinVersion: tlsMinVer,

		// ACME (Let's Encrypt)
		TLSAutocertEnable:   acmeEnable,
		TLSAutocertEmail:    acmeEmail,
		TLSAutocertHosts:    acmeHosts,
		TLSAutocertCacheDir: acmeCache,
		TLSACMEDirectoryURL: acmeDirURL,

		// PFX/PKCS#12
		TLSPFXFile:     pfxFile,
		TLSPFXPassword: pfxPass,

		// TLS advanced
		TLS12CipherSuites: tls12Suites,

		// CSR generation
		TLSGenerateCSR:   genCSR,
		TLSCSRCommonName: csrCN,
		TLSCSRHosts:      csrHosts,
		TLSCSROrg:        csrOrg,
		TLSCSROutDir:     csrOut,
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
