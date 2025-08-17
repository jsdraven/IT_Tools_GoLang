// Package logging_test: black-box tests for the log package API surface.
package logging_test

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jsdraven/IT_Tools_GoLang/pkg/config"
	"github.com/jsdraven/IT_Tools_GoLang/pkg/logging"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// helper to grab and parse the last slog JSON object in buffer
func lastLogJSON(t *testing.T, buf *bytes.Buffer) map[string]any {
	t.Helper()
	data := bytes.TrimSpace(buf.Bytes())
	require.NotEmpty(t, data, "expected at least one log line")
	lines := bytes.Split(data, []byte{'\n'})
	var m map[string]any
	require.NoError(t, json.Unmarshal(lines[len(lines)-1], &m))
	return m
}

func TestNew_LogLevels(t *testing.T) {
	cfg := &config.Config{LogLevel: 0} // LevelInfo default (0)
	var buf bytes.Buffer
	logger := logging.New(cfg, &buf)

	logger.Debug("debug_message")
	logger.Info("info_message")
	logger.Warn("warn_message")

	out := buf.String()
	assert.Contains(t, out, `"level":"INFO","msg":"info_message"`)
	assert.Contains(t, out, `"level":"WARN","msg":"warn_message"`)
	assert.NotContains(t, out, `"level":"DEBUG","msg":"debug_message"`)
}

func TestMiddleware_BasicRequestLogging(t *testing.T) {
	cfg := config.Load()
	var buf bytes.Buffer
	logger := logging.New(cfg, &buf)

	final := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		if n, err := w.Write([]byte("OK")); err != nil || n != len("OK") {
			t.Fatalf("write failed: n=%d err=%v", n, err)
		}
	})

	h := logging.Middleware(cfg, logger)(final)

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/testpath", nil)
	h.ServeHTTP(rr, req)

	require.Equal(t, http.StatusOK, rr.Code)
	m := lastLogJSON(t, &buf)
	assert.Equal(t, "http_request", m["msg"])
	assert.Equal(t, "GET", m["method"])
	assert.Equal(t, "/testpath", m["path"])
	assert.EqualValues(t, 200, m["status"])
}

func TestMiddleware_PathSkipping(t *testing.T) {
	cfg := config.Load()
	cfg.LogSkipPaths = []string{"/healthz"}

	var buf bytes.Buffer
	logger := logging.New(cfg, &buf)

	r := chi.NewRouter()
	// Route outside middleware: simulates "skip" via config path match
	r.Group(func(gr chi.Router) {
		gr.Use(logging.Middleware(cfg, logger))
		gr.Get("/api/echo", func(w http.ResponseWriter, r *http.Request) {
			if _, err := w.Write([]byte("echo")); err != nil {
				t.Fatalf("write failed: %v", err)
			}
		})
	})
	// Health route still goes through router; middleware itself will skip logging for /healthz
	r.Get("/healthz", func(w http.ResponseWriter, r *http.Request) {
		if _, err := w.Write([]byte("OK")); err != nil {
			t.Fatalf("write failed: %v", err)
		}
	})

	// Hit skipped path
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	r.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Empty(t, bytes.TrimSpace(buf.Bytes()), "no logs should be emitted for /healthz")

	// Hit non-skipped path
	buf.Reset()
	rr2 := httptest.NewRecorder()
	req2 := httptest.NewRequest(http.MethodGet, "/api/echo", nil)
	r.ServeHTTP(rr2, req2)
	require.Equal(t, http.StatusOK, rr2.Code)
	require.NotEmpty(t, bytes.TrimSpace(buf.Bytes()))
	m := lastLogJSON(t, &buf)
	assert.Equal(t, "/api/echo", m["path"])
}

// TestNew_NilConfig_DefaultLevel verifies that passing a nil config defaults to LevelInfo.
func TestNew_NilConfig_DefaultLevel(t *testing.T) {
	var buf bytes.Buffer
	logger := logging.New(nil, &buf) // nil cfg → LevelInfo branch

	logger.Debug("debug_message") // should be filtered out
	logger.Info("info_message")
	logger.Warn("warn_message")

	out := buf.String()
	require.NotEmpty(t, out)
	assert.NotContains(t, out, `"level":"DEBUG","msg":"debug_message"`)
	assert.Contains(t, out, `"level":"INFO","msg":"info_message"`)
	assert.Contains(t, out, `"level":"WARN","msg":"warn_message"`)
}

// TestNew_FileWrite_ToLogFile_WhenNoWriterProvided exercises the "open it_tools.log" branch.
func TestNew_FileWrite_ToLogFile_WhenNoWriterProvided(t *testing.T) {
	tDir := t.TempDir()
	oldWD, err := os.Getwd()
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.Chdir(oldWD) })
	require.NoError(t, os.Chdir(tDir))

	cfg := &config.Config{LogLevel: slog.LevelInfo, Env: "prod"}
	logger := logging.New(cfg) // no writer → opens/creates "it_tools.log"

	// Emit one line
	logger.Info("file_ok")

	// Read and assert before trying to delete (Windows keeps the writer handle open)
	p := filepath.Join(tDir, "it_tools.log")
	data, err := os.ReadFile(p)
	require.NoError(t, err)
	out := string(bytes.TrimSpace(data))
	require.NotEmpty(t, out, "expected log file to contain at least one line")
	assert.Contains(t, out, `"level":"INFO"`)
	assert.Contains(t, out, `"msg":"file_ok"`)

	// Drop references to logger so the os.File can be finalized/closed.
	logger = nil
	runtime.GC()

	// Retry remove; Windows finalizers aren’t immediate.
	var removeErr error
	for i := 0; i < 10; i++ {
		removeErr = os.Remove(p)
		if removeErr == nil {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	require.NoError(t, removeErr, "failed to remove it_tools.log (file handle likely still open)")
}

// TestNew_FallbackToStderr_OnOpenFailure forces OpenFile to fail and asserts the error was logged via slog.Default.
func TestNew_FallbackToStderr_OnOpenFailure(t *testing.T) {
	tDir := t.TempDir()
	oldWD, err := os.Getwd()
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.Chdir(oldWD) })
	require.NoError(t, os.Chdir(tDir))

	// Create a DIRECTORY named "it_tools.log" so os.OpenFile(path, ...) fails.
	require.NoError(t, os.Mkdir("it_tools.log", 0o755))

	// Capture slog.Default() output to verify the fallback error message.
	var dflt bytes.Buffer
	restore := swapDefaultToBuffer(&dflt, slog.LevelDebug)
	t.Cleanup(restore)

	cfg := &config.Config{LogLevel: slog.LevelInfo, Env: "prod"}
	logger := logging.New(cfg) // triggers os.OpenFile failure → logs error to slog.Default and falls back to stderr
	require.NotNil(t, logger)

	errOut := dflt.String()
	require.NotEmpty(t, errOut, "expected default logger to record an error")
	assert.Contains(t, errOut, "Failed to open log file") // message from log.go
}

// swapDefaultToBuffer replaces slog.Default() with a buffer-backed JSON logger; returns restore func.
func swapDefaultToBuffer(out io.Writer, lvl slog.Level) func() {
	old := slog.Default()
	new := slog.New(slog.NewJSONHandler(out, &slog.HandlerOptions{Level: lvl}))
	slog.SetDefault(new)
	return func() { slog.SetDefault(old) }
}
