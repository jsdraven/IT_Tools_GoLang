package log

import (
	"io"
	"log/slog"
	"os"

	"github.com/jsdraven/IT_Tools_GoLang/internal/config"
)

// New initializes a new slog.Logger based on the application config.
// It accepts an optional io.Writer to override the default file output,
// which is primarily used for testing.
func New(cfg *config.Config, w ...io.Writer) *slog.Logger {
	var output io.Writer

	// If a writer is provided (for tests), use the first one.
	if len(w) > 0 && w[0] != nil {
		output = w[0]
	} else {
		// Otherwise, open the log file for production use.
		logFile, err := os.OpenFile("it_tools.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o666)
		if err != nil {
			slog.Error("Failed to open log file, falling back to stderr", "error", err)
			output = os.Stderr // Fallback to standard error
		} else {
			output = logFile
		}
	}

	// This check handles the case where a nil config is passed.
	var level slog.Level
	if cfg != nil {
		level = cfg.LogLevel
	} else {
		level = slog.LevelInfo // Safe default
	}

	handlerOpts := &slog.HandlerOptions{
		Level: level,
	}

	return slog.New(slog.NewJSONHandler(output, handlerOpts))
}
