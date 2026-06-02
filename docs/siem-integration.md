# SIEM Integration Guide

Project Titan features a decoupled **Audit Hook** architecture designed for seamless integration with third-party security modules (e.g., Sentinel 1, Splunk, or custom monitoring agents). 

This guide explains how the integration works and how to develop a plugin that consumes our security events.

## Architecture Overview

The integration relies on a **Producer-Consumer** pattern using an asynchronous event bus.

1.  **The Producer (Audit Hook):** A specialized middleware layer in the application kernel that monitors incoming HTTP requests. It intercepts critical status codes (401, 403, 429) and converts them into structured `AuditEvent` objects.
2.  **The Bus (`EventDispatcher`):** An abstraction layer that manages event distribution. It allows any number of independent subscribers to listen for events without the kernel knowing who they are.
3.  **The Consumer (Security Plugin):** An external module (like Sentinel 1) that subscribes to the `EventDispatcher`. When an event is dispatched, the plugin receives the structured data and can perform high-level logic like threat intelligence lookups or alerting.

## The Event Schema

Every security event follows a strictly typed structure defined in `pkg/events/audit_event.go`:

| Field | Type | Description |
| :--- | :--- | :--- |
| `ID` | `string` (UUID) | Unique identifier for the specific event instance. |
| `Timestamp` | `time.Time` | The exact moment the security incident was detected. |
| `Severity` | `Severity` | `INFO`, `WARNING`, `CRITICAL`, or `ALERT`. |
| `EventType` | `string` | Categorization (e.g., `auth_failure`, `rate_limit_exceeded`). |
| `Actor` | `string` | The source of the request (IP Address, User ID, or User Agent). |
| `Resource` | `string` | The URI path or component being targeted. |
| `Action` | `string` | The HTTP method used (`GET`, `POST`, etc.). |
| `Metadata` | `map[string]interface{}` | Contextual data (e.g., Request Headers, User-Agent). |

## Developing a Security Plugin (Example: Sentinel 1)

To integrate a new security tool, follow these three steps:

### 1. Implement the Subscriber
Your plugin must implement a function that matches the `func(events.AuditEvent)` signature. This function will be called every time a security event occurs.

### 2. Register with the Dispatcher
During your plugin's initialization phase, obtain a reference to the application's `EventDispatcher` and call the `.Subscribe()` method.

### 3. Execute Detection Logic
Inside your subscriber function, implement your proprietary detection algorithms (e.g., checking an IP against a blacklist or detecting brute-force patterns).

#### **Example Implementation (Go)**

```go
package sentinel1

import (
	"fmt"
	"IT_Tools_GoLang_New/pkg/events"
)

type Sentinel1Plugin struct {
	dispatcher events.EventDispatcher
}

func NewSentinel1Plugin(d events.EventDispatcher) *Sentinel1Plugin {
	return &Sentinel1Plugin{dispatcher: d}
}

func (s *Sentinel1Plugin) Start() {
	fmt.Println("🛡️ Sentinel 1: Monitoring active.")
	// Registering the plugin to the audit hook bus
	s.dispatcher.Subscribe(s.onAuditEvent)
}

func (s *Sentinel1Plugin) onAuditEvent(event events.AuditEvent) {
	// Perform threat intelligence or alerting logic here
	if event.Severity == events.SeverityCritical {
		fmt.Printf("[ALERT] High-risk access blocked: %s at %s\n", event.Resource, event.Actor)
	}
}
```

## Summary of Benefits
*   **Decoupling:** The core application remains lightweight and unaware of the plugin's internal logic.
*   **Extensibility:** Multiple plugins can subscribe to the same event stream simultaneously without interference.
*   **Resilience:** A failure in a security plugin does not impact the availability of the main web service.
