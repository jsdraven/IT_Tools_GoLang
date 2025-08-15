// Package rateban: per-IP rate limit + auto-ban middleware.
//
// SPDX-License-Identifier: AGPL-3.0-or-later
package rateban

import (
	"encoding/json"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/time/rate"

	"github.com/jsdraven/IT_Tools_GoLang/internal/config"
)

type rateBan struct {
	mu        sync.Mutex
	limits    map[string]*rate.Limiter // ip -> limiter
	hits      map[string][]time.Time   // ip -> timestamps of 429s
	bans      map[string]time.Time     // ip -> ban expiry
	cfg       *config.Config
	logger    *slog.Logger
	nowFunc   func() time.Time
	stopSweep chan struct{}
	lastSweep time.Time
}

func NewRateBan(cfg *config.Config, logger *slog.Logger) *rateBan {
	rb := &rateBan{
		limits:    make(map[string]*rate.Limiter),
		hits:      make(map[string][]time.Time),
		bans:      make(map[string]time.Time),
		cfg:       cfg,
		logger:    logger,
		nowFunc:   time.Now,
		stopSweep: make(chan struct{}),
	}
	// Background maintenance: unban expired + prune old hits for idle IPs.
	// Use BanWindowSeconds as a natural sweep interval floor; cap it so it’s not too chatty.
	interval := time.Duration(max(15, min(120, cfg.BanWindowSeconds/2))) * time.Second
	go func() {
		tk := time.NewTicker(interval)
		defer tk.Stop()
		for {
			select {
			case <-tk.C:
				rb.sweepOnce(rb.now())
			case <-rb.stopSweep:
				return
			}
		}
	}()

	// background sweep to drop expired bans and old hit entries
	return rb
}

// sweepOnce performs a single maintenance pass. Exported to tests via same package.
func (rb *rateBan) sweepOnce(now time.Time) {
	rb.mu.Lock()

	// Stage unbanned IPs to log outside the lock
	var unbanned []string

	// Unban expired
	for ip, exp := range rb.bans {
		if now.After(exp) {
			delete(rb.bans, ip)
			unbanned = append(unbanned, ip)
		}
	}

	// Prune old 429 hits outside window
	win := time.Duration(rb.cfg.BanWindowSeconds) * time.Second
	for ip, arr := range rb.hits {
		j := 0
		for _, ts := range arr {
			if now.Sub(ts) <= win {
				arr[j] = ts // compact in-place
				j++
			}
		}
		if j == 0 {
			// remove map entry entirely to keep map small
			delete(rb.hits, ip)
		} else {
			rb.hits[ip] = arr[:j]
		}
	}

	rb.mu.Unlock()

	// Log outside the critical section
	for _, ip := range unbanned {
		rb.logger.Info("ip_unbanned", "ip", ip, "time", now)
	}
}

func (rb *rateBan) maybeSweep(now time.Time) {
	// sweep at most once per ~BanWindow
	win := time.Duration(rb.cfg.BanWindowSeconds) * time.Second
	if win <= 0 {
		win = 60 * time.Second
	}
	rb.mu.Lock()
	if rb.lastSweep.IsZero() || now.Sub(rb.lastSweep) >= win {
		rb.lastSweep = now
		rb.mu.Unlock() // unlock before doing the real sweep (it locks internally)
		rb.sweepOnce(now)
		return
	}
	rb.mu.Unlock()
}

func (rb *rateBan) now() time.Time {
	f := rb.nowFunc // read once to avoid races if tests swap it
	if f != nil {
		return f()
	}
	return time.Now()
}

func (rb *rateBan) limiterFor(ip string) *rate.Limiter {
	rb.mu.Lock()
	defer rb.mu.Unlock()
	lim, ok := rb.limits[ip]
	if !ok {
		// convert ints to rate.Limit
		lim = rate.NewLimiter(rate.Limit(rb.cfg.RateLimitRPS), rb.cfg.RateLimitBurst)
		rb.limits[ip] = lim
	}
	return lim
}

func (rb *rateBan) recordHit(ip string) (hits int, banned bool, until time.Time) {
	rb.mu.Lock()
	defer rb.mu.Unlock()

	now := rb.now()
	win := time.Duration(rb.cfg.BanWindowSeconds) * time.Second

	arr := rb.hits[ip]
	arr = append(arr, now)
	// prune old entries
	j := 0
	for _, ts := range arr {
		if now.Sub(ts) <= win {
			arr[j] = ts
			j++
		}
	}
	arr = arr[:j]
	rb.hits[ip] = arr
	hits = len(arr)

	if hits > rb.cfg.BanThreshold {
		until = now.Add(time.Duration(rb.cfg.BanDurationSeconds) * time.Second)
		rb.bans[ip] = until
		delete(rb.hits, ip)
		banned = true
	}
	return
}

func (rb *rateBan) isBanned(ip string) (bool, time.Time) {
	rb.mu.Lock()
	defer rb.mu.Unlock()
	exp, ok := rb.bans[ip]
	if !ok {
		return false, time.Time{}
	}
	if rb.now().After(exp) {
		delete(rb.bans, ip)
		return false, time.Time{}
	}
	return true, exp
}

func (rb *rateBan) extractIP(r *http.Request) string {
	if rb.cfg.TrustProxy {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			// take first hop
			parts := strings.Split(xff, ",")
			ip := strings.TrimSpace(parts[0])
			// strip port if any
			if h, p, err := net.SplitHostPort(ip); err == nil && h != "" && p != "" {
				return h
			}
			return ip
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr // best effort
	}
	return host
}

// Middleware enforces rate limit and bans abusive IPs.
func (rb *rateBan) Middleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			rb.maybeSweep(rb.now())
			ip := rb.extractIP(r)

			// Already banned?
			if banned, until := rb.isBanned(ip); banned {
				rb.logger.Warn("ip_denied_banned", "ip", ip, "ban_expires", until)
				if rb.cfg.BanSilentDrop {
					// Try to drop the TCP connection without replying
					if hj, ok := w.(http.Hijacker); ok {
						if conn, _, err := hj.Hijack(); err == nil {
							_ = conn.Close()
							return
						}
					}
					// fallback: no hijack -> 403
				}
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}

			// Rate limit
			if !rb.limiterFor(ip).Allow() {
				h, banned, until := rb.recordHit(ip)
				rb.logger.Warn("rate_limited", "ip", ip, "hits", h, "limit_rps", rb.cfg.RateLimitRPS, "burst", rb.cfg.RateLimitBurst)
				if banned {
					rb.logger.Error("ip_banned", "ip", ip, "ban_expires", until)
					if rb.cfg.BanSilentDrop {
						if hj, ok := w.(http.Hijacker); ok {
							if conn, _, err := hj.Hijack(); err == nil {
								_ = conn.Close()
								return
							}
						}
						// fallback: no hijack -> 403
						http.Error(w, "forbidden", http.StatusForbidden)
						return
					}
					http.Error(w, "forbidden", http.StatusForbidden)
					return
				}
				http.Error(w, "too many requests", http.StatusTooManyRequests)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// HandleListBans returns a JSON map { "ip": "expiryRFC3339", ... }.
func (rb *rateBan) HandleListBans() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		rb.sweepOnce(rb.now())
		type row struct {
			IP     string `json:"ip"`
			Expire string `json:"expire"`
		}
		out := []row{}
		now := rb.now()
		rb.mu.Lock()
		for ip, exp := range rb.bans {
			if now.Before(exp) {
				out = append(out, row{IP: ip, Expire: exp.UTC().Format(time.RFC3339)})
			}
		}
		rb.mu.Unlock()

		w.Header().Set("Content-Type", "application/json")
		enc := json.NewEncoder(w)
		_ = enc.Encode(out)
	}
}

// optional helper if you ever need to stop the sweeper (e.g., tests/shutdown)
func (rb *rateBan) StopSweeper() { close(rb.stopSweep) }

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
