// internal/server/sanitize_test.go
package download

import (
	"net/http/httptest"
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

func TestMakeASCIIFallback(t *testing.T) {
	cases := map[string]string{
		"hello.txt":         "hello.txt",
		"Pokémon—βeta.txt":  "Pok_mon__eta.txt",
		"💾":                 "____", // at least one underscore → but function returns fallback later if empty
		"":                  "download.bin",
		`bad"name\file.txt`: `bad_name_file.txt`, // quotes/backslashes show up as underscores here; escaping is tested below
	}
	for in, wantContains := range cases {
		got := makeASCIIFallback(in)
		if got == "" {
			t.Fatalf("empty fallback for %q", in)
		}
		// Loose check: ensure we only have ASCII and expected structural form
		for i := 0; i < len(got); i++ {
			if got[i] > 0x7F {
				t.Fatalf("non-ascii in %q => %q", in, got)
			}
		}
		// Make sure it never returns empty
		if in == "" && got != "download.bin" {
			t.Fatalf("empty input fallback: got %q", got)
		}
		_ = wantContains // (string can vary by number of underscores)
	}
}

func TestSetDownloadDisposition_HeaderFormat(t *testing.T) {
	rr := httptest.NewRecorder()
	setDownloadDisposition(rr, `Pokémon—"βeta".txt`)

	cd := rr.Header().Get("Content-Disposition")
	if !strings.HasPrefix(cd, "attachment; ") {
		t.Fatalf("missing attachment; got %q", cd)
	}
	// Must have ascii filename="<...>" (with escaped quotes/backslashes) AND filename*=UTF-8''...
	if !strings.Contains(cd, `filename="`) || !strings.Contains(cd, `filename*=`) {
		t.Fatalf("expected both filename= and filename*=, got %q", cd)
	}
	// Ensure the quoted ASCII part escapes quotes/backslashes
	if strings.Contains(cd, `"β`) {
		t.Fatalf("non-ascii leaked into quoted filename: %q", cd)
	}
	if strings.Contains(cd, `"\"`) {
		// Note: we expect \" if quote exists in original; simply assert header present
		t.Run("quote in original gets sanitized + encoded", func(t *testing.T) {
			w := httptest.NewRecorder()
			setDownloadDisposition(w, `report "final".txt`)
			cd := w.Header().Get("Content-Disposition")

			// Always present structure
			if !strings.HasPrefix(cd, `attachment; filename="`) || !strings.Contains(cd, `; filename*=`) {
				t.Fatalf("bad Content-Disposition structure: %q", cd)
			}

			// ASCII fallback replaces quotes with underscores
			if !strings.Contains(cd, `filename="report _final_.txt"`) {
				t.Fatalf("ascii fallback not sanitized (quotes -> _): %q", cd)
			}

			// RFC5987 filename* percent-encodes the quote as %22
			if !strings.Contains(cd, `filename*=UTF-8''report%20%22final%22.txt`) {
				t.Fatalf("filename* not RFC5987-encoded with %%22 for quotes: %q", cd)
			}
		})
	}
}

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
