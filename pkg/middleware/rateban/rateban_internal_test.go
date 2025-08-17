package rateban

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/jsdraven/IT_Tools_GoLang/pkg/config"
)

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func TestRateBan_ExtractIP_Variants(t *testing.T) {
	cfg := config.Load()
	cfg.TrustProxy = false
	rb := NewRateBan(cfg, discardLogger())

	// No proxy: RemoteAddr host:port
	req := httptest.NewRequest(http.MethodGet, "http://svc.local/x", nil)
	req.RemoteAddr = "203.0.113.9:12345"
	if ip := rb.extractIP(req); ip != "203.0.113.9" {
		t.Fatalf("extractIP (no proxy): got %q", ip)
	}

	// With proxy + XFF single IP (no port)
	cfg.TrustProxy = true
	rb = NewRateBan(cfg, discardLogger())
	req2 := httptest.NewRequest(http.MethodGet, "http://svc.local/x", nil)
	req2.Header.Set("X-Forwarded-For", "198.51.100.10")
	if ip := rb.extractIP(req2); ip != "198.51.100.10" {
		t.Fatalf("extractIP (xff w/o port): got %q", ip)
	}

	// With proxy + XFF includes port
	req3 := httptest.NewRequest(http.MethodGet, "http://svc.local/x", nil)
	req3.Header.Set("X-Forwarded-For", "198.51.100.11:555, 198.51.100.12")
	if ip := rb.extractIP(req3); ip != "198.51.100.11" {
		t.Fatalf("extractIP (xff w/ port): got %q", ip)
	}

	// With proxy but empty XFF -> fallback to RemoteAddr
	req4 := httptest.NewRequest(http.MethodGet, "http://svc.local/x", nil)
	req4.RemoteAddr = "203.0.113.77:2222"
	if ip := rb.extractIP(req4); ip != "203.0.113.77" {
		t.Fatalf("extractIP (empty xff): got %q", ip)
	}
}

func TestRateBan_SweepOnce_UnbanAndPrune(t *testing.T) {
	cfg := config.Load()
	cfg.BanWindowSeconds = 60
	rb := NewRateBan(cfg, discardLogger())

	now := time.Date(2025, 8, 10, 12, 0, 0, 0, time.UTC)

	// Set one expired and one active ban
	rb.mu.Lock()
	rb.bans["198.51.100.1"] = now.Add(-time.Minute) // expired
	rb.bans["198.51.100.2"] = now.Add(time.Minute)  // active
	// Hits: one old, one fresh for IP3
	old := now.Add(-2 * time.Minute)
	rb.hits["198.51.100.3"] = []time.Time{old, now.Add(-10 * time.Second)}
	rb.mu.Unlock()

	rb.sweepOnce(now)

	rb.mu.Lock()
	defer rb.mu.Unlock()
	if _, ok := rb.bans["198.51.100.1"]; ok {
		t.Fatal("expired ban not removed")
	}
	if _, ok := rb.bans["198.51.100.2"]; !ok {
		t.Fatal("active ban removed unexpectedly")
	}
	if hits := rb.hits["198.51.100.3"]; len(hits) != 1 {
		t.Fatalf("expected pruned hits len=1, got %d", len(hits))
	}
}

func TestRateBan_IsBanned_States(t *testing.T) {
	cfg := config.Load()
	rb := NewRateBan(cfg, discardLogger())

	// none
	if b, _ := rb.isBanned("203.0.113.1"); b {
		t.Fatal("expected not banned")
	}

	// active
	now := time.Now()
	rb.mu.Lock()
	rb.bans["203.0.113.2"] = now.Add(1 * time.Minute)
	rb.mu.Unlock()
	if b, _ := rb.isBanned("203.0.113.2"); !b {
		t.Fatal("expected banned")
	}

	// expired -> auto-unban on check
	rb.mu.Lock()
	rb.bans["203.0.113.3"] = now.Add(-1 * time.Minute)
	rb.mu.Unlock()
	if b, _ := rb.isBanned("203.0.113.3"); b {
		t.Fatal("expected expired ban to be cleared")
	}
}

func TestRateBan_Now_DefaultVsCustom(t *testing.T) {
	cfg := config.Load()
	rb := NewRateBan(cfg, discardLogger())

	// Custom nowFunc
	ref := time.Date(2025, 8, 10, 12, 0, 0, 0, time.UTC)
	rb.nowFunc = func() time.Time { return ref }
	if got := rb.now(); !got.Equal(ref) {
		t.Fatalf("now() custom mismatch: %v", got)
	}

	// Nil nowFunc -> real time (just verify it doesn't panic)
	rb.nowFunc = nil
	_ = rb.now()
}

func TestRateBan_StopSweeper(t *testing.T) {
	// Setup: Create an instance of rateBan with an open channel
	rb := &rateBan{
		stopSweep: make(chan struct{}),
	}

	// Execute the method we're testing
	rb.StopSweeper()

	// Verification: Check if the channel is actually closed.
	// The `<-rb.stopSweep` read will not block.
	// `ok` will be `false` if the channel is closed.
	select {
	case _, ok := <-rb.stopSweep:
		if ok {
			t.Error("stopSweep channel was not closed, but a value was received")
		}
		// If !ok, the test passes because the channel is closed as expected.
	default:
		// This case should not be reached if the channel is closed.
		// If it is, it means the channel is still open and would block.
		t.Error("stopSweep channel was not closed, as a read would block")
	}
}

// Optional: Test for panic on double-close
func TestRateBan_StopSweeper_PanicsOnDoubleClose(t *testing.T) {
	// Setup
	rb := &rateBan{
		stopSweep: make(chan struct{}),
	}
	rb.StopSweeper() // First close

	// Defer a function to recover from the expected panic
	defer func() {
		if r := recover(); r == nil {
			t.Error("The code did not panic on second call to StopSweeper")
		}
	}()

	// Execute the second call, which should panic
	rb.StopSweeper()
}
