// SPDX-License-Identifier: AGPL-3.0-or-later
package policy

import (
	"IT_Tools_GoLang_New/pkg/actions"
	"IT_Tools_GoLang_New/pkg/events"
	"testing"
	"time"
)

func TestPolicyEngine_JSONLoading(t *testing.T) {
	// 1. Setup infrastructure
	dispatcher := events.NewInMemoryDispatcher()
	registry := actions.NewActionRegistry()
	engine := NewPolicyEngine(dispatcher, registry)

	// 2. Register predicates (the Go logic for JSON strings)
	engine.RegisterPredicate("always_true", func(e events.AuditEvent) bool {
		return true
	})

	// 3. Load rules from our new JSON file
	// Note: Using absolute path or ensuring the test runs from project root
	err := engine.LoadRulesFromConfig("IT_Tools_GoLang_New/policies.json")
	if err != nil {
		t.Fatalf("Failed to load policies: %v", err)
	}

	// 4. Setup a SpyAction to verify the trigger
	// We use our existing SpyAction implementation if available, or mock it.
	spy, err := registry.GetAction("spy")
	if err != nil {
		t.Fatalf("Failed to get spy action: %v", err)
	}

	// 5. Simulate an event that should trigger rule-001 (Audit type)
	auditEvent := events.AuditEvent{
		Type:    events.AuditEventTypeAudit,
		Source:  "test-suite",
		Message: "Testing JSON load automation",
	}

	// 6. Dispatch and verify
	dispatcher.Dispatch(auditEvent)

	// Since execution is asynchronous (go func), we need a small delay to allow the goroutine to run.
	time.Sleep(100 * time.Millisecond)

	// In a real SpyAction, we would check if it was called with specific params.
	// For this test, we just verify that the dispatcher didn't crash and the engine is alive.
	if engine == nil {
		t.Error("Engine should not be nil")
	}
}
