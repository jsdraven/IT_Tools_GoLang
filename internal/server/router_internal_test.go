// Package server: router internal testing
package server

import (
	"strings"
	"testing"
)

func TestURLEncodeRFC5987(t *testing.T) {
	// RFC5987 form used in filename*
	in := "Pokémon—βeta.txt"
	got := urlEncodeRFC5987(in)
	if strings.Contains(got, " ") {
		t.Fatalf("should be percent-encoded, got %q", got)
	}
	// Safe ASCII should pass through
	if urlEncodeRFC5987("abc-_.123") != "abc-_.123" {
		t.Fatalf("safe chars should pass through")
	}
}
