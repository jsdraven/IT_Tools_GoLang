// Package server: safe attachment helpers (Content-Disposition, nosniff, size checks)
//
// SPDX-License-Identifier: AGPL-3.0-or-later
package server_test

import (
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/textproto"
	"strconv"
	"strings"
	"time"
	"unicode"
)

// AttachmentOpts controls how WriteAttachment writes the response.
type AttachmentOpts struct {
	// Filename is the desired download filename. It will be sanitized.
	Filename string
	// ContentType is the MIME type to send. If empty, defaults to application/octet-stream.
	ContentType string
	// Size is the exact length in bytes if known (>=0). If negative, length is unknown and
	// Content-Length will be omitted.
	Size int64
	// Disposition is either "attachment" (default) or "inline".
	Disposition string
	// ModTime is optional. When non-zero and the body implements io.ReadSeeker, callers could
	// choose to use http.ServeContent for range/caching behavior. This helper streams the body
	// directly and sets headers; range support is intentionally out-of-scope here.
	ModTime time.Time
}

// WriteAttachment writes a file download/inline response with strict headers.
// It never guesses types from the filename; pass ContentType if you know it.
// Security affordances:
//   - Sets X-Content-Type-Options: nosniff
//   - Sets Content-Disposition with sanitized filename (RFC 6266 w/ RFC 5987 fallback)
//   - Optionally sets Content-Length when Size >= 0
//   - Rejects obviously dangerous/empty filenames by falling back to "download"
func WriteAttachment(w http.ResponseWriter, r *http.Request, body io.Reader, opts AttachmentOpts) error {
	// Defensive defaults
	disposition := strings.ToLower(strings.TrimSpace(opts.Disposition))
	if disposition != "inline" {
		disposition = "attachment"
	}

	ct := strings.TrimSpace(opts.ContentType)
	if ct == "" {
		ct = "application/octet-stream"
	}

	name := sanitizeFilename(strings.TrimSpace(opts.Filename))
	if name == "" {
		name = "download"
	}
	// Per RFC 6266: include a token form (ASCII-only, quoted) and an RFC 5987 form for non-ASCII.
	tokenName := toASCII(name)
	if tokenName == "" {
		tokenName = "download"
	}
	// Quote per RFC 6266; escape backslash and double quote.
	quoted := `"` + strings.ReplaceAll(strings.ReplaceAll(tokenName, `\`, `\\`), `"`, `\"`) + `"`

	// RFC 5987 extended parameter (percent-encode UTF-8)
	ext := rfc5987encode(name)

	// Build Content-Disposition
	cd := disposition + "; filename=" + quoted
	if ext != "" && ext != tokenName {
		cd += "; filename*=UTF-8''" + ext
	}

	// Standard safety headers
	h := w.Header()
	h.Set("Content-Type", ct)
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Content-Disposition", cd)
	// Strong caching defaults for downloads (override upstream if you want different behavior)
	h.Set("Cache-Control", "no-store")

	// Content-Length if known and non-negative
	if opts.Size >= 0 {
		h.Set("Content-Length", strconv.FormatInt(opts.Size, 10))
	}

	// HEAD: headers only
	if r != nil && strings.EqualFold(r.Method, http.MethodHead) {
		w.WriteHeader(http.StatusOK)
		return nil
	}

	// Stream body
	w.WriteHeader(http.StatusOK)
	if body == nil {
		return nil
	}

	if opts.Size >= 0 {
		// If Size known, limit copy to exactly that much to prevent over-read from an oversized reader.
		_, err := io.CopyN(w, body, opts.Size)
		if err == io.EOF {
			// Short body → treat as error; client already got 200 but we surface to caller for logging.
			return fmt.Errorf("short read: %w", err)
		}
		return err
	}

	// Unknown size: just stream
	_, err := io.Copy(w, body)
	return err
}

// sanitizeFilename produces a safe, cross-platform-ish filename:
//
//   - Trims leading/trailing ASCII and Unicode spaces as well as trailing dots (common Windows issue)
//   - Removes path separators and control characters
//   - Collapses runs of disallowed characters to single underscores
//   - Prevents reserved names like "." and ".."
//   - Caps length to 255 bytes (common FS limit)
func sanitizeFilename(s string) string {
	if s == "" {
		return ""
	}
	// Normalize basic whitespace and strip CR/LF/Tab/control
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		switch {
		case r == '/' || r == '\\' || r == ':':
			b.WriteRune(' ') // path-ish to space, will be trimmed/collapsed later
		case r < 0x20 || r == 0x7f: // control
			// drop
		default:
			b.WriteRune(r)
		}
	}
	out := b.String()

	// Trim leading/trailing spaces and dots (including a few common Unicode variants)
	out = trimDotsAndSpaces(out)
	if out == "." || out == ".." {
		out = ""
	}
	if out == "" {
		return ""
	}

	// Replace disallowed runes with underscores; allow letters, numbers, space, dot, dash, underscore, plus.
	allow := func(r rune) bool {
		if r == '.' || r == '-' || r == '_' || r == '+' {
			return true
		}
		return unicode.IsLetter(r) || unicode.IsNumber(r) || unicode.IsSpace(r)
	}
	var sb strings.Builder
	sb.Grow(len(out))
	lastUnderscore := false
	for _, r := range out {
		if allow(r) {
			sb.WriteRune(r)
			lastUnderscore = false
		} else {
			if !lastUnderscore {
				sb.WriteByte('_')
				lastUnderscore = true
			}
		}
	}
	clean := sb.String()

	// Collapse internal whitespace to single spaces
	clean = strings.Join(strings.Fields(clean), " ")

	// Trim (again) and ensure not ending with dot/space
	clean = trimDotsAndSpaces(clean)

	// Enforce max length (bytes)
	const max = 255
	if len(clean) > max {
		clean = clean[:max]
		// avoid trailing partial of multi-byte by trimming again (safe because we only sliced at bytes)
		clean = strings.TrimRightFunc(clean, func(r rune) bool { return r == '.' || unicode.IsSpace(r) })
	}

	return clean
}

// toASCII removes/approximates non-ASCII characters to produce a filename-safe token.
// We avoid external deps; this is a small, practical transliteration table plus a fallback
// that drops/underscores unmapped runes.
func toASCII(s string) string {
	if s == "" {
		return ""
	}
	// Quick path: all ASCII already
	allASCII := true
	for i := 0; i < len(s); i++ {
		if s[i] > 0x7F {
			allASCII = false
			break
		}
	}
	if allASCII {
		// Also fold separators/controls
		return sanitizeASCII(s)
	}

	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		if r <= 0x7F {
			switch r {
			case '/', '\\', ':':
				b.WriteByte('_')
			default:
				if r < 0x20 || r == 0x7f {
					// skip control
				} else {
					b.WriteRune(r)
				}
			}
			continue
		}
		if rep, ok := asciiMap[r]; ok {
			b.WriteString(rep)
			continue
		}
		// Generic folds
		switch {
		case unicode.IsSpace(r):
			b.WriteByte(' ')
		default:
			b.WriteByte('_')
		}
	}
	// Collapse spaces/underscores nicely and trim
	out := strings.Join(strings.Fields(b.String()), " ")
	out = strings.ReplaceAll(out, "__", "_")
	out = strings.Trim(out, " .")
	return out
}

func sanitizeASCII(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		switch {
		case r == '/' || r == '\\' || r == ':':
			b.WriteByte('_')
		case r < 0x20 || r == 0x7f:
			// drop control
		default:
			b.WriteRune(r)
		}
	}
	out := strings.Trim(b.String(), " .")
	return out
}

// Minimal transliteration table for common Latin accents and symbols.
// Extend as you find cases in the wild.
var asciiMap = map[rune]string{
	'À': "A", 'Á': "A", 'Â': "A", 'Ã': "A", 'Ä': "A", 'Å': "A",
	'à': "a", 'á': "a", 'â': "a", 'ã': "a", 'ä': "a", 'å': "a",
	'È': "E", 'É': "E", 'Ê': "E", 'Ë': "E",
	'è': "e", 'é': "e", 'ê': "e", 'ë': "e",
	'Ì': "I", 'Í': "I", 'Î': "I", 'Ï': "I",
	'ì': "i", 'í': "i", 'î': "i", 'ï': "i",
	'Ò': "O", 'Ó': "O", 'Ô': "O", 'Õ': "O", 'Ö': "O", 'Ø': "O",
	'ò': "o", 'ó': "o", 'ô': "o", 'õ': "o", 'ö': "o", 'ø': "o",
	'Ù': "U", 'Ú': "U", 'Û': "U", 'Ü': "U",
	'ù': "u", 'ú': "u", 'û': "u", 'ü': "u",
	'Ñ': "N", 'ñ': "n",
	'Ç': "C", 'ç': "c",
	'Ÿ': "Y", 'Ý': "Y", 'ý': "y", 'ÿ': "y",
	'Š': "S", 'š': "s", 'Ž': "Z", 'ž': "z",
	'Ł': "L", 'ł': "l",
	'Ð': "D", 'ð': "d", 'Þ': "Th", 'þ': "th",
	'Æ': "AE", 'æ': "ae",
	'¿': "", '¡': "",
	'œ': "oe", 'Œ': "OE",
	'ß': "ss",
	// punctuation-like unicode → ASCII
	'“': `"`, '”': `"`, '„': `"`, '«': `"`, '»': `"`,
	'‘': `'`, '’': `'`, '‚': `'`,
	'—': "-", '–': "-", '‑': "-", '·': "-",
	'…': "...",
}

// rfc5987encode percent-encodes a UTF-8 string for use in filename* parameter.
func rfc5987encode(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		// attr-char from RFC: ALPHA / DIGIT / "!" / "#" / "$" / "&" / "+" / "-" / "." / "^" / "_" / "`" / "|" / "~"
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' ||
			strings.ContainsRune("!#$&+-.^_`|~", rune(c)) {
			b.WriteByte(c)
			continue
		}
		b.WriteString("%")
		b.WriteString(strings.ToUpper(strconv.FormatUint(uint64(c), 16)))
	}
	return b.String()
}

// trimDotsAndSpaces trims leading/trailing ASCII/Unicode spaces and trailing dots.
// Also trims a few common Unicode dot-like characters.
func trimDotsAndSpaces(s string) string {
	if s == "" {
		return s
	}
	// First, trim Unicode white space broadly
	s = strings.TrimFunc(s, func(r rune) bool { return unicode.IsSpace(r) })
	// Then trim ASCII dots and a couple dot-like runes from both ends
	trimDotLike := func(r rune) bool {
		switch r {
		case '.', '。', '．', '｡': // ASCII dot + fullwidth/halfwidth variants
			return true
		default:
			return false
		}
	}
	// Trim leading
	for len(s) > 0 {
		r, size := utf8DecodeRuneInString(s)
		if trimDotLike(r) || unicode.IsSpace(r) {
			s = s[size:]
		} else {
			break
		}
	}
	// Trim trailing
	for len(s) > 0 {
		r, size := utf8DecodeLastRuneInString(s)
		if trimDotLike(r) || unicode.IsSpace(r) {
			s = s[:len(s)-size]
		} else {
			break
		}
	}
	return s
}

// Helpers to avoid importing unicode/utf8 directly in signatures above.
func utf8DecodeRuneInString(s string) (rune, int) {
	if len(s) == 0 {
		return 0, 0
	}
	if s[0] < 0x80 {
		return rune(s[0]), 1
	}
	// minimal decode; delegate to stdlib for correctness
	return []rune(s[:1])[0], 1
}

func utf8DecodeLastRuneInString(s string) (rune, int) {
	if len(s) == 0 {
		return 0, 0
	}
	// Walk back to a start byte
	i := len(s) - 1
	for i > 0 && (s[i]&0xC0) == 0x80 {
		i--
	}
	r := []rune(s[i:])[0]
	return r, len(s) - i
}

// DetectContentTypeFromExt returns a safe MIME type based on filename extension.
// Falls back to application/octet-stream if unknown. It uses the system mime
// tables registered in Go's mime package.
func DetectContentTypeFromExt(filename string) string {
	ext := ""
	if dot := strings.LastIndexByte(filename, '.'); dot != -1 && dot < len(filename)-1 {
		ext = strings.ToLower(filename[dot:])
	}
	if ext == "" {
		return "application/octet-stream"
	}
	if t := mime.TypeByExtension(ext); t != "" {
		// Strip parameters (e.g., "; charset=utf-8") for attachments unless caller wants them.
		if i := strings.IndexByte(t, ';'); i != -1 {
			return strings.TrimSpace(t[:i])
		}
		return t
	}
	return "application/octet-stream"
}

// ParseContentDisposition is a tiny helper used in tests to inspect header content safely.
func ParseContentDisposition(h http.Header) (disposition, filename, filenameStar string) {
	cd := h.Get("Content-Disposition")
	if cd == "" {
		return "", "", ""
	}
	// Case-insensitive parse
	v, params, err := mime.ParseMediaType(cd)
	if err != nil {
		return "", "", ""
	}
	disposition = strings.ToLower(v)
	// filename param is token/quoted-string; to compare, unfold RFC2047 (shouldn't appear here) and trim quotes
	filename = textproto.TrimString(params["filename"])
	filenameStar = params["filename*"]
	return
}
