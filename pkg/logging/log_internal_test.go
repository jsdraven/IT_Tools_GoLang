// Package logging: white-box tests for internal helpers and middleware behavior.
package logging

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5/middleware"
	"github.com/jsdraven/IT_Tools_GoLang/pkg/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// runMiddlewareOnce wraps finalHandler with Middleware(cfg, logger) and calls ServeHTTP directly.
// This keeps server-side control (RemoteAddr, headers, URL) and avoids client RequestURI issues.
func runMiddlewareOnce(t *testing.T, cfg *config.Config, req *http.Request) (status int, logLine map[string]any, raw string) {
	t.Helper()

	var buf bytes.Buffer
	logger := New(cfg, &buf)

	finalHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		if n, err := w.Write([]byte("OK")); err != nil || n != len("OK") {
			t.Fatalf("write failed: n=%d err=%v", n, err)
		}
	})

	h := Middleware(cfg, logger)(finalHandler)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	raw = buf.String()
	if strings := bytes.TrimSpace([]byte(raw)); len(strings) == 0 {
		return rr.Code, nil, raw // caller can assert "no log emitted"
	}

	// Parse the single JSON log entry emitted by the middleware.
	// slog JSON handler writes one JSON object per line.
	lines := bytes.Split(bytes.TrimSpace([]byte(raw)), []byte{'\n'})
	last := lines[len(lines)-1]
	var m map[string]any
	require.NoError(t, json.Unmarshal(last, &m), "log line should be valid JSON")
	return rr.Code, m, raw
}

func TestMiddleware_InternalLogic(t *testing.T) {
	t.Run("IPExtraction", func(t *testing.T) {
		t.Run("TrustProxy_with_XFF", func(t *testing.T) {
			cfg := config.Load()
			cfg.TrustProxy = true

			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.Header.Set("X-Forwarded-For", "1.1.1.1, 2.2.2.2")
			req.RemoteAddr = "3.3.3.3:12345"

			code, m, _ := runMiddlewareOnce(t, cfg, req)
			require.Equal(t, http.StatusOK, code)
			require.NotNil(t, m)
			assert.Equal(t, "http_request", m["msg"])
			assert.Equal(t, "GET", m["method"])
			assert.Equal(t, "/", m["path"])
			assert.EqualValues(t, 200, m["status"])
			assert.Equal(t, "1.1.1.1", m["remote"])
		})

		t.Run("No_TrustProxy_falls_back_to_RemoteAddr", func(t *testing.T) {
			cfg := config.Load()
			cfg.TrustProxy = false

			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.Header.Set("X-Forwarded-For", "1.1.1.1")
			req.RemoteAddr = "3.3.3.3:12345"

			code, m, _ := runMiddlewareOnce(t, cfg, req)
			require.Equal(t, http.StatusOK, code)
			require.NotNil(t, m)
			assert.Equal(t, "3.3.3.3", m["remote"])
		})
	})

	t.Run("IPHashing", func(t *testing.T) {
		cfg := config.Load()
		cfg.LogHashIPs = true
		cfg.LogIPHashSalt = "test-salt"

		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.RemoteAddr = "1.2.3.4:5678"

		code, m, _ := runMiddlewareOnce(t, cfg, req)
		require.Equal(t, http.StatusOK, code)
		require.NotNil(t, m)
		// Should not log "remote", but should log "remote_hash".
		_, hasPlain := m["remote"]
		assert.False(t, hasPlain, "plain remote IP should not be present when hashing")
		hashVal, ok := m["remote_hash"].(string)
		require.True(t, ok)
		require.Len(t, hashVal, 32, "we log a 128-bit hex prefix")
	})

	t.Run("HeaderSanitization", func(t *testing.T) {
		cfg := config.Load()
		cfg.LogAllowedHeaders = []string{"Content-Type", "Authorization", "X-Request-Id"}
		cfg.LogRedactHeaders = []string{"Authorization"}

		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer secret-token")
		req.Header.Set("User-Agent", "should-NOT-be-logged")

		_, m, _ := runMiddlewareOnce(t, cfg, req)
		require.NotNil(t, m)

		hs, _ := m["headers"].(map[string]any)
		require.NotNil(t, hs, "headers object should be present")
		assert.Equal(t, "application/json", hs["Content-Type"])
		assert.Equal(t, "[REDACTED]", hs["Authorization"])
		_, exists := hs["User-Agent"]
		assert.False(t, exists, "User-Agent should not be present")
	})

	t.Run("QueryParameterLogging", func(t *testing.T) {
		t.Run("Includes_query_when_enabled", func(t *testing.T) {
			cfg := config.Load()
			cfg.LogIncludeQuery = true

			req := httptest.NewRequest(http.MethodGet, "/search?q=test", nil)
			_, m, _ := runMiddlewareOnce(t, cfg, req)
			require.Equal(t, "/search?q=test", m["path"])
		})
		t.Run("Excludes_query_when_disabled", func(t *testing.T) {
			cfg := config.Load()
			cfg.LogIncludeQuery = false

			req := httptest.NewRequest(http.MethodGet, "/search?q=test", nil)
			_, m, _ := runMiddlewareOnce(t, cfg, req)
			require.Equal(t, "/search", m["path"])
		})
	})
}

// Probe-point unit tests for helpers (kept lean & deterministic)

func Test_pathOf(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/p?x=1", nil)
	assert.Equal(t, "/p?x=1", pathOf(req, true))
	assert.Equal(t, "/p", pathOf(req, false))
}

func Test_shouldSkip(t *testing.T) {
	tests := []struct {
		name, path string
		skip       []string
		want       bool
	}{
		{"prefix match", "/health/live", []string{"/health"}, true},
		{"no match", "/api/v1", []string{"/health"}, false},
		{"empty list", "/health", nil, false},
		{"exact", "/status", []string{"/status"}, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, shouldSkip(tc.path, tc.skip))
		})
	}
}

func Test_extractIP(t *testing.T) {
	t.Run("TrustProxy uses first XFF", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("X-Forwarded-For", "1.1.1.1, 2.2.2.2")
		req.RemoteAddr = "3.3.3.3:12345"
		assert.Equal(t, "1.1.1.1", extractIP(req, true))
	})
	t.Run("No TrustProxy uses RemoteAddr", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("X-Forwarded-For", "1.1.1.1")
		req.RemoteAddr = "3.3.3.3:12345"
		assert.Equal(t, "3.3.3.3", extractIP(req, false))
	})
	t.Run("No XFF falls back to RemoteAddr", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.RemoteAddr = "3.3.3.3:12345"
		assert.Equal(t, "3.3.3.3", extractIP(req, true))
	})
}

func Test_pickHeaders(t *testing.T) {
	cfg := &config.Config{
		LogAllowedHeaders: []string{"Content-Type", "Authorization", "X-Request-Id"},
		LogRedactHeaders:  []string{"Authorization"},
	}
	h := http.Header{}
	h.Set("Content-Type", "application/json")
	h.Set("Authorization", "Bearer secret")
	h.Set("User-Agent", "ignore-me")

	got := pickHeaders(h, cfg)
	require.NotNil(t, got)
	assert.Equal(t, "application/json", got["Content-Type"])
	assert.Equal(t, "[REDACTED]", got["Authorization"])
	_, ok := got["User-Agent"]
	assert.False(t, ok)
}

func TestMiddleware_EmitsDurationAndBytes(t *testing.T) {
	cfg := config.Load()

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	code, m, _ := runMiddlewareOnce(t, cfg, req)

	require.Equal(t, http.StatusOK, code)
	require.NotNil(t, m)

	// Duration and bytes written should both be present
	_, hasDur := m["duration_ms"]
	_, hasBytes := m["bytes"]
	assert.True(t, hasDur, "duration_ms should be logged")
	assert.True(t, hasBytes, "bytes should be logged")
	assert.EqualValues(t, 2, m["bytes"], "middleware should count 2 bytes from 'OK'")
}

func TestMiddleware_EmitsRequestID(t *testing.T) {
	cfg := config.Load()

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	code, m, _ := runMiddlewareOnceWithReqID(t, cfg, req)

	require.Equal(t, http.StatusOK, code)
	require.NotNil(t, m)

	val, ok := m["request_id"].(string)
	require.True(t, ok, "request_id field should exist and be a string")
	require.NotEmpty(t, val, "request_id should not be empty")
}

func TestMiddleware_NoHeadersConfigured(t *testing.T) {
	cfg := config.Load()
	cfg.LogAllowedHeaders = nil // nothing allowed

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-Custom", "foo")

	_, m, _ := runMiddlewareOnce(t, cfg, req)
	require.NotNil(t, m)

	// With no allowed headers, "headers" key should be absent
	_, hasHeaders := m["headers"]
	assert.False(t, hasHeaders, "headers should not be logged when none are allowed")
}

// Like runMiddlewareOnce, but ensures chi's RequestID middleware runs first,
// so request_id is set and non-empty.
func runMiddlewareOnceWithReqID(t *testing.T, cfg *config.Config, req *http.Request) (status int, logLine map[string]any, raw string) {
	t.Helper()

	var buf bytes.Buffer
	logger := New(cfg, &buf)

	finalHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		if n, err := w.Write([]byte("OK")); err != nil || n != len("OK") {
			t.Fatalf("write failed: n=%d err=%v", n, err)
		}
	})

	// RequestID must run BEFORE your logging middleware
	h := middleware.RequestID(Middleware(cfg, logger)(finalHandler))

	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	raw = buf.String()
	if bytes.TrimSpace([]byte(raw)) == nil {
		return rr.Code, nil, raw
	}

	// parse last JSON line (use your existing parsing helper if you have one)
	lines := bytes.Split(bytes.TrimSpace([]byte(raw)), []byte{'\n'})
	last := lines[len(lines)-1]
	var m map[string]any
	require.NoError(t, json.Unmarshal(last, &m))
	return rr.Code, m, raw
}
