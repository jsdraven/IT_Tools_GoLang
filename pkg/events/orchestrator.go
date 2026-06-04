// SPDX-License-Identifier: AGPL-3.0-or-later
package events

import (
	"fmt"
	"sync"
)

// EventOrchestrator manages the lifecycle of an event, coordinating between 
// the high-speed Triage Dispatcher and the deep-inspection Policy Engine.
type EventOrchestrator struct {
	triage       TriageDispatcher
	policyEngine PolicyEngine
}

// TriageDispatcher defines the interface for the fast-path routing engine.
type TriageDispatcher interface {
	Dispatch(event AuditEvent) error
}

// PolicyEngine defines the interface for the context-aware rule evaluation engine.
type PolicyEngine interface {
	Evaluate(event AuditEvent) error
}

// NewEventOrchestrator initializes a new orchestrator with its required components.
func NewEventOrchestrator(triage TriageDispatcher, policy PolicyEngine) *EventOrchestrator {
	return &EventOrchestrator{
		triage:       triage,
		policyEngine: policy,
	}
}

// Process handles the end-to-end lifecycle of an incoming AuditEvent.
// It implements the "Tiered Response" strategy:
// 1. Attempt the "Fast Path" via Triage Dispatcher (O(1)).
// 2. If no route is found, fall back to the "Deep Inspection Path" via Policy Engine.
func (o *EventOrchestrator) Process(event AuditEvent) error {
	// --- Tier 1: The Reflex (Fast Path) ---
	err := o.triage.Dispatch(event)
	if err == nil {
		// A successful dispatch means the event was handled by a deterministic rule.
		return nil
	}

	// If we get here, the Triage layer couldn't find a specific route for this event type/severity.
	// We log this transition (in a real system) and move to Tier 2.
	
	// --- Tier 2: The Brain (Deep Inspection Path) ---
	// Fall back to the Policy Engine for complex, context-aware rule evaluation.
	err = o.policyEngine.Evaluate(event)
	if err != nil {
		return fmt.Errorf("policy engine evaluation failed: %w", err)
	}

	return nil
}
