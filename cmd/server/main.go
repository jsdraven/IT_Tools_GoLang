//go:build !cover

// Package main is the entrypoint for the IT_Tools_GoLang HTTP server.
// SPDX-License-Identifier: AGPL-3.0-or-later
package main

import (
	"context"
	"os"
	"os/signal"

	"github.com/jsdraven/IT_Tools_GoLang/internal/config"
	"github.com/jsdraven/IT_Tools_GoLang/internal/entry"
)

func main() {
	cfg := config.Load()
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	if err := entry.Run(ctx, cfg); err != nil {
		os.Exit(1)
	}
}
