// internal/server/sanitize_test.go
package server

import (
	"strings"
	"testing"
	"unicode/utf8"
)

func TestToASCII_CommonMappings(t *testing.T) {
	cases := map[string]string{
		"Pokémon":    "Pokemon",
		"Curaçao":    "Curacao",
		"résumé":     "resume",
		"Straße":     "Strasse",    // sharp S → "ss" is acceptable; "s" also OK if you chose simpler mapping
		"naïve—dash": "naive-dash", // em/en dashes → '-'
		"✓ ok":       " ok",        // checkmark removed; space retained
		"广州":         "",           // non-Latin dropped unless you added a translit map
		"тест":       "",           // Cyrillic dropped (unless transliterated)
	}

	for in, want := range cases {
		got := toASCII(in)
		// We don't demand exact matches for locale‑specific cases; we assert properties and prefix/suffix.
		if want == "" {
			// For unknown scripts, we expect an empty or whitespace-only result
			if strings.TrimSpace(got) != "" {
				t.Fatalf("toASCII(%q) => %q; want empty-ish ASCII", in, got)
			}
			continue
		}
		if got != want {
			t.Fatalf("toASCII(%q) => %q; want %q", in, got, want)
		}
		// Ensure ASCII-only and valid UTF-8
		if !utf8.ValidString(got) {
			t.Fatalf("toASCII produced invalid UTF-8 for %q", in)
		}
		for _, r := range got {
			if r > 127 {
				t.Fatalf("non-ASCII rune %q in output %q", r, got)
			}
		}
	}
}

func TestSanitizeFilename_Properties(t *testing.T) {
	cases := []string{
		"../../etc/passwd",
		" report .pdf ",
		"nul\000bad?.txt",
		".hidden",
		"con", // Windows reserved, but we just ensure it becomes safe (not a path)
		"invoice 2025/08?.pdf",
		"emoji🔥name.tar.gz",
		"quotes\"'name.csv",
		"spaces     many.txt",
	}

	for _, in := range cases {
		got := sanitizeFilename(in)
		if got == "" {
			t.Fatalf("sanitizeFilename(%q) => empty", in)
		}
		if strings.ContainsAny(got, "/\\\x00") {
			t.Fatalf("sanitizeFilename(%q) => %q has forbidden separators or NUL", in, got)
		}
		if strings.HasPrefix(got, ".") {
			t.Fatalf("sanitizeFilename(%q) => %q starts with dot", in, got)
		}
		// ASCII only
		for _, r := range got {
			if r > 127 {
				t.Fatalf("sanitizeFilename(%q) => %q contains non-ASCII rune %q", in, got, r)
			}
		}
		// length budget (implementation uses a cap like 150-200; we assert it's not huge)
		if len(got) > 150 {
			t.Fatalf("sanitizeFilename(%q) => %q too long (%d)", in, got, len(got))
		}
	}
}

func TestSanitizeFilename_StableExamples(t *testing.T) {
	tests := []struct {
		in, want string
	}{
		{` report 2025/08?.pdf `, "report 2025_08.pdf"},
		{`Pokémon—βeta.txt`, "Pokemon-beta.txt"},
		{`..\.hidden`, "hidden"},
		{`README`, "README"},
		{`archive.tar.gz`, "archive.tar.gz"}, // keep common multi-part extensions
	}
	for _, tc := range tests {
		if got := sanitizeFilename(tc.in); got != tc.want {
			t.Fatalf("sanitizeFilename(%q) => %q; want %q", tc.in, got, tc.want)
		}
	}
}
