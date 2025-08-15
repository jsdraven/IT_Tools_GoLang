// Package entry: Redirect helps with auto switching http redirect to https
package entry

import (
	"net"
	"net/http"

	"github.com/jsdraven/IT_Tools_GoLang/internal/config"
)

// wantHTTPRedirect decides whether to run an HTTP->HTTPS redirect listener.
// If HTTPS_REDIRECT is explicitly set, honor it; otherwise:
//   - real certs (ACME/PFX/PEM): redirect
//   - self-signed: no redirect
func wantHTTPRedirect(cfg *config.Config, usingSelfSigned bool) bool {
	if cfg.HTTPSRedirectSet {
		return cfg.HTTPSRedirect
	}
	return !usingSelfSigned
}

func redirectToHTTPSHandler(tlsAddr string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := r.Host
		// Preserve non-default TLS ports (e.g., :8080 in dev).
		if h, p, err := net.SplitHostPort(tlsAddr); err == nil && p != "" && p != "443" {
			if hh, _, err2 := net.SplitHostPort(host); err2 == nil {
				host = hh
			}
			if h != "" {
				host = h + ":" + p
			} else {
				host = host + ":" + p
			}
		} else {
			if hh, _, err2 := net.SplitHostPort(host); err2 == nil {
				host = hh
			}
		}
		target := "https://" + host + r.URL.RequestURI()
		http.Redirect(w, r, target, http.StatusPermanentRedirect) // 308
	})
}
