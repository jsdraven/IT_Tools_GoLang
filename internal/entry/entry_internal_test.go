package entry

import (
	"context"
	"log/slog"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/jsdraven/IT_Tools_GoLang/pkg/config"
)

type recordingHandler struct {
	mu      sync.Mutex
	records []slog.Record
}

func (h *recordingHandler) Enabled(context.Context, slog.Level) bool { return true }

func (h *recordingHandler) Handle(ctx context.Context, r slog.Record) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.records = append(h.records, r.Clone())
	return nil
}

func (h *recordingHandler) WithAttrs(attrs []slog.Attr) slog.Handler { return h }
func (h *recordingHandler) WithGroup(name string) slog.Handler       { return h }

func (h *recordingHandler) has(msg string) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, r := range h.records {
		if r.Message == msg {
			return true
		}
	}
	return false
}

func waitForMessage(h *recordingHandler, msg string, d time.Duration) bool {
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if h.has(msg) {
			return true
		}
		time.Sleep(10 * time.Millisecond)
	}
	return h.has(msg)
}

func TestServeOnListener_LogsLifecycle(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	cfg := config.Load()
	cfg.TLSAutocertEnable = false
	cfg.TLSPFXFile = ""
	cfg.TLSCertFile = ""
	cfg.TLSKeyFile = ""
	cfg.HTTPSRedirect = false
	cfg.HTTPSRedirectSet = true

	h := &recordingHandler{}
	logger := slog.New(h)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		_ = ServeOnListener(ctx, ln, cfg, logger)
		close(done)
	}()

	if !waitForMessage(h, "using_self_signed_tls", time.Second) {
		t.Fatal("missing using_self_signed_tls log")
	}

	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("server did not shut down in time")
	}

	if !h.has("server_listening") {
		t.Error("missing server_listening log")
	}
	if !h.has("server_stopped") {
		t.Error("missing server_stopped log")
	}
}
