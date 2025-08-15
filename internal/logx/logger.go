// Package logx:  This is the application logger.
package logx

import (
	"log/slog"
	"os"
)

// New is a logger constructs a JSON slog logger at the desired level.
func New(level slog.Level) *slog.Logger {
	return slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: level}))
}
