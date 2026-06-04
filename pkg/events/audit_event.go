// SPDX-License-Identifier: AGPL-3.0-or-later
package events

import (
	"time"
)

// Severity represents the importance level of an audit event.
type Severity string

const (
	SeverityInfo     Severity = "INFO"
	SeverityWarning  Severity = "WARNING"
	SeverityCritical Severity = "CRITICAL"
	SeverityAlert    Severity = "ALERT"
)

// AuditEvent represents a structured security event captured by the SIEM audit hook.
type AuditEvent struct {
	ID        string                 `json:"id"`
	Timestamp time.Time              `json:"timestamp"`
	Severity  Severity               `json:"severity"`
	EventType string                 `json:"event_type"` // e.g., "auth_failure", "rate_limit_exceeded"
	Actor     string                 `json:"actor"`      // IP address, User ID, or User Agent
	Resource  string                 `json:"resource"`   // The URI or component being accessed
	Action    string                 `json://action"`    // The operation attempted (e.g., "GET", "POST")
	Metadata  map[string]interface{} `json:"metadata"`   // Additional context
}

// EventDispatcher defines the interface for broadcasting events to various subscribers.
type EventDispatcher interface {
	Dispatch(event AuditEvent) error
	Subscribe(handler func(AuditEvent))
}
