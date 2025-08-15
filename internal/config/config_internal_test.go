// Package config: config_internal_test helps test non exported functions.
package config

import (
	"log/slog"
	"testing"
)

func TestParseLevelTable(t *testing.T) {
	cases := []struct {
		in   string
		want slog.Level
	}{
		{"DEBUG", slog.LevelDebug},
		{"Warn", slog.LevelWarn},
		{"error", slog.LevelError},
		{"INFO", slog.LevelInfo}, // explicit
		{"", slog.LevelInfo},     // default on empty/unknown
		{"nope", slog.LevelInfo}, // default on unknown
	}
	for _, tc := range cases {
		if got := parseLevel(tc.in); got != tc.want {
			t.Fatalf("parseLevel(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

func TestGetenvBoolDefault(t *testing.T) {
	t.Setenv("XBOOL", "YES")
	if !getenvBoolDefault("XBOOL", false) {
		t.Fatal("YES => true")
	}
	t.Setenv("XBOOL", "off")
	if getenvBoolDefault("XBOOL", true) {
		t.Fatal("off => false")
	}
}

func TestGetenvIntDefault(t *testing.T) {
	t.Setenv("XINT", "42")
	if getenvIntDefault("XINT", 0) != 42 {
		t.Fatal("want 42")
	}
	t.Setenv("XINT", "notnum")
	if getenvIntDefault("XINT", 7) != 7 {
		t.Fatal("bad int => default")
	}
}

func TestSplitCSV(t *testing.T) {
	out := splitCSV(" a, ,b , c ")
	if len(out) != 3 || out[0] != "a" || out[1] != "b" || out[2] != "c" {
		t.Fatalf("bad split: %#v", out)
	}
}
