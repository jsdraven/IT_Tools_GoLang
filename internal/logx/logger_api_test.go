// Package logx_test internal/logx/logger_test.go
package logx_test

import (
	"io"
	"log/slog"
	"testing"

	"github.com/jsdraven/IT_Tools_GoLang/internal/logx"
)

func TestNew(t *testing.T) {
	l := logx.New(slog.LevelInfo)
	if l == nil {
		t.Fatal("expected non-nil logger")
	}
	// Optional: write to io.Discard for sanity
	l = slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelDebug}))
	_ = l
}
