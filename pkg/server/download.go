// Package server
// internal/server/download.go
package server

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type AttachmentOpts struct {
	Filename    string    // download name presented to the browser
	ContentType string    // fallback to application/octet-stream if empty
	Size        int64     // pass -1 if unknown; if >=0 we set Content-Length and enforce it
	ETag        string    // optional
	ModTime     time.Time // optional; enables ServeContent if Reader is io.ReadSeeker
	CacheCtrl   string    // optional; e.g. "private, max-age=0, must-revalidate"
}

func WriteAttachment(w http.ResponseWriter, r *http.Request, src io.Reader, opts AttachmentOpts) error {
	name := sanitizeFilename(opts.Filename)
	if name == "" {
		name = "download"
	}

	ct := opts.ContentType
	if strings.TrimSpace(ct) == "" {
		ct = "application/octet-stream"
	}

	asciiName := toASCII(name)
	rfc5987 := url.PathEscape(name)
	cd := fmt.Sprintf(`attachment; filename="%s"; filename*=UTF-8''%s`, asciiName, rfc5987)

	h := w.Header()
	h.Set("Content-Type", ct)
	h.Set("Content-Disposition", cd)
	h.Set("X-Content-Type-Options", "nosniff") // defensive; also set globally

	if opts.ETag != "" {
		h.Set("ETag", opts.ETag)
	}
	if opts.CacheCtrl != "" {
		h.Set("Cache-Control", opts.CacheCtrl)
	}

	// If we have an io.ReadSeeker and ModTime, let ServeContent handle ranges.
	if rs, ok := src.(io.ReadSeeker); ok && !opts.ModTime.IsZero() {
		// Do NOT set Content-Length when delegating to ServeContent; it will compute.
		http.ServeContent(w, r, name, opts.ModTime, rs)
		return nil
	}

	// Otherwise stream manually. Enforce Content-Length if Size >= 0.
	if opts.Size >= 0 {
		h.Set("Content-Length", fmt.Sprintf("%d", opts.Size))
		lr := &io.LimitedReader{R: src, N: opts.Size}
		n, err := io.Copy(w, lr)
		if err != nil {
			return err
		}
		if n != opts.Size || lr.N != 0 {
			// Either source ended early or wrote too much; fail hard.
			return fmt.Errorf("mismatched content length: wrote=%d want=%d", n, opts.Size)
		}
		return nil
	}

	// Unknown length path: just stream (no Content-Length)
	_, err := io.Copy(w, src)
	return err
}

// sanitizeFilename produces a safe, stable filename for downloads.
func sanitizeFilename(s string) string {
	// 1) strip CR/LF and trim outer space
	s = strings.ReplaceAll(s, "\r", "")
	s = strings.ReplaceAll(s, "\n", "")
	s = strings.TrimSpace(s)

	// 2) ASCII‑only transliteration (drops emoji etc.)
	s = toASCII(s)

	// 3) convert path separators and whitespace to underscores
	//    (do NOT call filepath.Base — tests want earlier segments kept)
	s = strings.ReplaceAll(s, "/", "_")
	s = strings.ReplaceAll(s, "\\", "_")
	// collapse runs of spaces into single spaces (keeps the space in "report 2025")
	var tmp strings.Builder
	lastSpace := false
	for _, r := range s {
		if r == ' ' {
			if !lastSpace {
				tmp.WriteByte(' ')
				lastSpace = true
			}
			continue
		}
		tmp.WriteRune(r)
		lastSpace = false
	}
	s = tmp.String()

	// 4) allowlist: letters, digits, space, dot, underscore, hyphen; drop everything else
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z',
			r >= 'A' && r <= 'Z',
			r >= '0' && r <= '9',
			r == ' ', r == '.', r == '_', r == '-':
			b.WriteRune(r)
			// drop others
		}
	}
	out := b.String()

	// 5) collapse multiple underscores
	for strings.Contains(out, "__") {
		out = strings.ReplaceAll(out, "__", "_")
	}

	// 6) avoid underscore just before dot: "08_.pdf" -> "08.pdf"
	out = strings.ReplaceAll(out, "_.", ".")

	// 7) trim leading dots/spaces/underscores/dashes (e.g., ".hidden" -> "hidden")
	out = strings.TrimLeft(out, ". _-")
	// and trailing dots/spaces
	out = strings.TrimRight(out, ". ")

	if strings.TrimSpace(out) == "" {
		return "download"
	}
	return out
}

// makeASCIIFallback returns an ASCII-only representation of name, replacing any
// non-ASCII or disallowed characters with underscores. If the resulting string
// is empty, a safe default is returned.
func makeASCIIFallback(name string) string {
	if name == "" {
		return "download.bin"
	}
	var b strings.Builder
	for _, r := range name {
		if r < 128 && r != '"' && r != '\\' {
			b.WriteRune(r)
		} else {
			b.WriteByte('_')
		}
	}
	out := b.String()
	if strings.TrimSpace(out) == "" {
		return "download.bin"
	}
	return out
}

// setDownloadDisposition writes a Content-Disposition header using both a
// sanitized ASCII filename and an RFC 5987 encoded UTF-8 filename parameter.
func setDownloadDisposition(w http.ResponseWriter, name string) {
	ascii := makeASCIIFallback(name)
	rfc5987 := url.PathEscape(name)
	cd := fmt.Sprintf("attachment; filename=\"%s\"; filename*=UTF-8''%s", ascii, rfc5987)
	w.Header().Set("Content-Disposition", cd)
}

// toASCII transliterates common accented characters to plain ASCII
// and drops any remaining non-ASCII runes.
// toASCII transliterates common accented characters to plain ASCII,
// maps Unicode dashes to '-', expands select ligatures (ß→ss, æ→ae, œ→oe),
// and expands Greek beta to "beta". Any other non-ASCII runes are dropped.
// toASCII transliterates a subset of common runes to plain ASCII.
// - Accented Latin letters → base letter (é→e, ñ→n, …)
// - Unicode dashes (—, – , −) → '-'
// - Greek beta (β/Β) → 'b'/'B'  (note: NOT "beta")
// - Curly quotes → straight quotes
// - Everything else non-ASCII is dropped.
// toASCII transliterates common non-ASCII characters to plain ASCII.
// - Uses a small fast table for single-rune replacements.
// - Handles multi-rune cases like 'ß' → "ss", 'æ' → "ae".
// - Converts en/em dash to '-' to preserve separators.
// - Drops anything still non-ASCII.
func toASCII(s string) string {
	// Multi-rune expansions first (map to string).
	multi := map[rune]string{
		'ß': "ss",
		'Æ': "AE", 'æ': "ae",
		'Œ': "OE", 'œ': "oe",
		'Ø': "O", 'ø': "o",
		'Ð': "D", 'ð': "d",
		'Þ': "TH", 'þ': "th",
		'Ł': "L", 'ł': "l",
		// punctuation/separators we want to keep as ASCII equivalents
		'–': "-", // en dash
		'—': "-", // em dash
		'−': "-", // minus sign
		'’': "'", '‘': "'", '“': `"`, '”': `"`,
	}

	// Common one-to-one Latin letters with diacritics.
	single := map[rune]rune{
		'à': 'a', 'á': 'a', 'â': 'a', 'ä': 'a', 'ã': 'a', 'å': 'a', 'ā': 'a',
		'ç': 'c', 'č': 'c',
		'è': 'e', 'é': 'e', 'ê': 'e', 'ë': 'e', 'ē': 'e',
		'ì': 'i', 'í': 'i', 'î': 'i', 'ï': 'i', 'ī': 'i',
		'ñ': 'n',
		'ò': 'o', 'ó': 'o', 'ô': 'o', 'ö': 'o', 'õ': 'o', 'ō': 'o',
		'ù': 'u', 'ú': 'u', 'û': 'u', 'ü': 'u', 'ū': 'u',
		'ý': 'y', 'ÿ': 'y',
		'À': 'A', 'Á': 'A', 'Â': 'A', 'Ä': 'A', 'Ã': 'A', 'Å': 'A', 'Ā': 'A',
		'Ç': 'C', 'Č': 'C',
		'È': 'E', 'É': 'E', 'Ê': 'E', 'Ë': 'E', 'Ē': 'E',
		'Ì': 'I', 'Í': 'I', 'Î': 'I', 'Ï': 'I', 'Ī': 'I',
		'Ñ': 'N',
		'Ò': 'O', 'Ó': 'O', 'Ô': 'O', 'Ö': 'O', 'Õ': 'O', 'Ō': 'O',
		'Ù': 'U', 'Ú': 'U', 'Û': 'U', 'Ü': 'U', 'Ū': 'U',
		'Ý': 'Y',
		// a couple of helpful extras seen in tests
		'β': 'b', // Greek small beta
	}

	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		if r < 128 {
			// ASCII fast path
			b.WriteRune(r)
			continue
		}
		if rep, ok := multi[r]; ok {
			b.WriteString(rep)
			continue
		}
		if rep, ok := single[r]; ok {
			b.WriteRune(rep)
			continue
		}
		// otherwise: drop this rune
	}
	return b.String()
}
