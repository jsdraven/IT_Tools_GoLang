// SPDX-License-Identifier: AGPL-3.0-or-later
package audit

import (
	"net/http"
	"time"

	"IT_Tools_GoLang_New/pkg/events"

	"github.com/google/uuid"
)

// AuditMiddleware wraps an http.Handler to intercept and record security-relevant events.
type AuditMiddleware struct {
	dispatcher events.EventDispatcher
}

// NewAuditMiddleware creates a new instance of the audit middleware.
func NewAuditMiddleware(dispatcher events.EventDispatcher) *AuditMiddleware {
	return &AuditMiddleware{
		dispatcher: dispatcher,
	}
}

// Handler implements the http.Handler interface.
func (m *AuditMiddleware) Handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// We use a custom response writer to capture the status code of the response.
		rw := &responseWriter{ResponseWriter: w, statusCode: http.StatusOK}

		// Proceed with the request chain.
		next.ServeHTTP(rw, r)

		// After the handler has finished, we check if the response indicates a security event.
		if m.isSecurityEvent(rw.statusCode) {
			m.captureEvent(r, rw.statusCode)
		}
	})
}

// isSecurityEvent determines if the HTTP status code represents a noteworthy security incident.
func (m *AuditMiddleware) isSecurityEvent(code int) bool {
	return code == http.StatusUnauthorized || // 401
		code == http.StatusForbidden || // 403
		code == http.StatusTooManyRequests // 429
}

// captureEvent constructs and dispatches an AuditEvent based on the request and response.
func (m *AuditMiddleware) captureEvent(r *http.Request, statusCode int) {
	severity := events.SeverityWarning
	if statusCode == http.StatusForbidden {
		severity = events.SeverityCritical
	} else if statusCode == http.StatusTooManyRequests {
		severity = events.SeverityAlert
	}

	eventType := "unauthorized_access"
	if statusCode == http.StatusTooManyRequests {
		eventType = "rate_limit_exceeded"
	} else if statusCode == http.StatusUnauthorized {
		eventType = "authentication_failure"
	}

	event := events.AuditEvent{
		ID:        uuid.New().String(),
		Timestamp: time.Now(),
		Severity:  severity,
		EventType: eventType,
		Actor:     r.RemoteAddr, // In production, this should be extracted from auth context/headers.
		Resource:  r.URL.Path,
		Action:    r.Method,
		Metadata: map[string]interface{}{
			"user_agent": r.UserAgent(),
			"status":     statusCode,
		},
	}

	// Dispatch the event to all subscribers (the SIEM engine).
	_ = m.dispatcher.Dispatch(event)
}

// responseWriter is a decorator for http.ResponseWriter that captures the status code.
type responseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rwrw := rw.ResponseWriter
	rwrw.WriteHeader(code)
}
