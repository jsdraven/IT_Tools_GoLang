// SPDX-License-Identifier: AGPL-3.0-or-later
package triage

import (
	"testing"

	"github.com/jsdraven/IT_Tools_GoLang_New/pkg/actions"
	"github.com/jsdraven/IT_Tools_GoLang_New/pkg/events"
)

// MockAction is a simple implementation of ActionDriver for testing.
type MockAction struct {
	name    string
	called  bool
	payload map[string]interface{}
}

func (m *MockAction) Name() string { return m.name }
func (m *MockAction) Execute(params map[string]interface{}) error {
	m.called = true
	m.payload = params
	return nil
}

func TestDispatcher_Dispatch(t *testing.T) {
	registry := actions.NewRegistry()
	mockAction := &MockAction{name: "test-action"}
	_ = registry.Register(mockAction)

	dispatcher := NewDispatcher(registry)
	// Register a route for an auth failure with critical severity
	dispatcher.RegisterRoute("auth_failure:CRITICAL", "test-action")

	t.Run("Successful Fast-Path Dispatch", func(t *testing.T) {
		event := events.AuditEvent{
			ID:        "123",
			Severity:  events.SeverityCritical,
			EventType: "auth_failure",
			Actor:     "192.168.1.1",
		}

		err := dispatcher.Dispatch(event)
		if err != nil {
			t.Errorf("Expected successful dispatch, got error: %v", err)
		}

		if !mockAction.called {
			t.Error("Expected action to be called")
		}

		if mockAction.payload["event_id"] != "123" {
			t.Errorf("Expected event_id 123, got %v", mockAction.payload["event_id"])
		}
	})

	t.Run("No Route Found - Fallback Required", func(t *testing.T) {
		// Event type that isn't registered in the dispatcher
		event := events.AuditEvent{
			ID:        "456",
			Severity:  events.SeverityInfo,
			EventType: "unknown_event",
		}

		err := dispatcher.Dispatch(event)
		if err == nil {
			t.Error("Expected error due to missing route, but got none")
		}
	})

	t.Run("Route Points to Non-Existent Action", func(t *testing.T) {
		dispatcher.RegisterRoute("broken:route", "ghost-action")
		event := events.AuditEvent{
			ID:        "789",
			Severity:  events.SeverityWarning,
			EventType: "broken",
		}

		err := dispatcher.Dispatch(event)
		if err == nil {
			t.Error("Expected error due to missing action in registry, but got none")
		}
	})
}
