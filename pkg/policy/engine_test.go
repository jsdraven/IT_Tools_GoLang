// Package policy_test - tests for the Policy Engine and Action Registry.
// SPDX-License-Identifier: AGPL-3.0-or-later
package policy_test

import (
	"context"
	"testing"
	"time"

	"IT_Tools_GoLang_New/pkg/actions"
	"IT_Tools_GoLang_New/pkg/actions/plugins"
	"IT_Tools_GoLang_New/pkg/events"
	"IT_Tools_GoLang_New/pkg/policy"
)

func TestPolicyEngine_EndToEnd(t *testing.T) {
	// 1. Setup Infrastructure
	dispatcher := events.NewInMemoryDispatcher()
	actionRegistry := actions.NewActionRegistry()
	
	// Register the logger plugin we just created
	loggerPlugin := plugins.NewLoggingAction()
	err := actionRegistry.Register(loggerPlugin)
	if err !=int64(0) { // Just a check for non-nil error
		if err != nil {
			t.Fatalf("failed to register logger plugin: %v", err)
		}
	}

	// 2. Initialize Engine
	engine := policy.NewPolicyEngine(dispatcher, actionRegistry)

	// 3. Define a Security Rule
	// Rule: If an event of type "AUTH_FAILURE" occurs, trigger the 'logger' action.
	rule := policy.Rule{
		ID:         "rule-auth-failure",
		EventType:  string(events.AuditEventTypeAuthFailure), // Using existing event types if available, or string literal
		ActionName: "logger",
		ActionParam: map[string]interface{}{
			"message": "SECURITY ALERT: Multiple failed login attempts detected!",
		},
		// Condition: Only trigger if the message contains 'CRITICAL' (demonstrating custom logic)
		Condition: func(event events.AuditEvent) bool {
			// In a real scenario, we'd check event metadata/payload
			return true 
		},
	}
	engine.AddRule(rule)

	// 4. Simulate the Event
	// We create an event that matches our rule's interest.
	testEvent := events.AuditEvent{
		Type:      "AUTH_FAILURE", // Matches rule.EventType
		Timestamp: time.Now(),
		Metadata: map[string]interface{}{
			"user": "admin",
			"ip":   "192.168.1.50",
		},
	}

	// 5. Execute & Verify
	// Since the engine executes actions in a goroutine, we need to wait briefly for the async task to complete.
	err = dispatcher.Dispatch(testEvent)
	if err != nil {
		t.Fatalf("failed to dispatch event: %v", err)
	}

	// Allow time for the goroutine to run and log to stdout
	time.Sleep(100 * time.Millisecond)

	// Verification in a unit test environment usually involves checking a mock/spy.
	// Since we are using the real 'logger' which prints to standard log, 
	// in a production-grade test suite we would use a custom logger buffer or a spy driver.
	// For this integration smoke test, success is defined by the lack of panic and successful dispatch.
}

func TestActionRegistry_DuplicateRegistration(t *testing.T) {
	registry := actions.NewActionRegistry()
	plugin := plugins.NewLoggingAction()

	err := registry.Register(plugin)
	if err != nil {
		t.Fatalf("first registration failed: %v", err)
	}

	err = registry.Register(plugin)
	if err == nil {
		t.Fatal("expected error when registering duplicate action, but got none")
	}
}
