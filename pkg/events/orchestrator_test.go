// SPDX-License-Identifier: AGPL-3.0-or-later
package events

import (
	"fmt"
	"testing"
)

// MockTriage implements TriageDispatcher for testing.
type MockTriage struct {
	dispatchCalled bool
	shouldFail     bool
}

func (m *MockTriage) Dispatch(event AuditEvent) error {
	m.dispatchCalled = true
	if m.shouldFail {
		return fmt.Errorf("no route found")
	}
	return nil
}

// MockPolicy implements PolicyEngine for testing.
type MockPolicy struct {
	evaluateCalled bool
	shouldFail     bool
}

func (m *MockPolicy) Evaluate(event AuditEvent) error {
	m.evaluateCalled = true
	if m.shouldFail {
		return fmt.Errorf("policy evaluation failed")
	}
	return nil
}

func TestEventOrchestrator_Process(t *testing.T) {
	t.Run("Successful Fast-Path Dispatch", func(t *testing.T) {
		mockTriage := &MockTriage{shouldFail: false}
		mockPolicy := &MockPolicy{}
		orchestrator := NewEventOrchestrator(mockTriage, mockPolicy)

		event := AuditEvent{ID: "1", EventType: "test"}

		err := orchestrator.Process(event)
		if err != nil {
			t.Errorf("Expected success on fast-path, got error: %v", err)
		}

		if !mockTriage.dispatchCalled {
			t.Error("Expected Triage to be called")
		}

		if mockPolicy.evaluateCalled {
			t.Error("Expected Policy Engine NOT to be called on fast-path success")
		}
	})

	t.Run("Fallback to Policy Engine on Triage Failure", func(t *testing.T) {
		mockTriage := &MockTriage{shouldFail: true}
		mockPolicy := &MockPolicy{}
		orchestrator := NewEventOrchestrator(mockTriage, mockPolicy)

		event := AuditEvent{ID: "2", EventType: "test"}

		err := orchestrator.Process(event)
		if err != nil {
			t.Errorf("Expected success on fallback to policy engine, got error: %v", err)
		}

		if !mockTriage.dispatchCalled {
			t.Error("Expected Triage to be

		}

		if !mockPolicy.evaluateCalled {
			t.Error("Expected Policy Engine TO BE CALLED on triage failure")
		}
	})

	t.Run("Failure in Policy Engine Propagates", func(t *testing.T) {
		mockTriage := &MockTriage{shouldFail: true}
		mockPolicy := &MockPolicy{shouldFail: true}
		orchestrator := NewEventOrchestrator(mockTriage, mockPolicy)

		event := AuditEvent{ID: "3", EventType: "test"}

		err := orchestrator.Process(event)
		if err == nil {
			t.Error("Expected error from policy engine, but got none")
		}
	})
}
