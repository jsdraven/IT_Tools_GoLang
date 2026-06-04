// SPDX-License-Identifier: AGPL-3.0-or-later
package triage

import (
	"fmt"
	"sync"

	"github.com/jsdraven/IT_Tools_GoLang_New/pkg/actions"
	"github.com/jsdraven/IT_Tools_GoLang_New/pkg/events"
)

// Dispatcher manages the high-speed routing of events to specific actions based on routing keys.
type Dispatcher struct {
	registry *actions.Registry
	// routes maps a routing key (e.g., "auth_failure:critical") to an action name.
	routes sync.Map // map[string]string
}

// NewDispatcher initializes a new Triage Dispatcher with an action registry.
func NewDispatcher(registry *actions.Registry) *Dispatcher {
	return &Dispatcher{
		registry: registry,
	}
}

// RegisterRoute maps a specific event routing key to an action name in the registry.
// The routing key should follow the pattern "{event_type}:{severity}".
func (d *Dispatcher) RegisterRoute(eventKey string, actionName string) {
	d.routes.Store(eventKey, actionName)
}

// Dispatch attempts to route an incoming AuditEvent using the fast-path map lookup.
// If no matching routing key is found, it returns an error (which signals the caller 
// to fall back to the Policy Engine).
func (d *Dispatcher) Dispatch(event events.AuditEvent) error {
	// Generate the routing key: "{event_type}:{severity}"
	routingKey := fmt.Sprintf("%s:%s", event.EventType, event.Severity)

	val, ok := d.routes.Load(routingKey)
	if !ok {
		return fmt.Errorf("no fast-path route found for key: %s", routingKey)
	}

	actionName := val.(string)
	action, err := d.registry.Get(actionName)
	if err != nil {
		return fmt.Errorf("route points to missing action '%s': %w", actionName, err)
	}

	// Execute the action. 
	// In a real system, we might pass the event through a context or as part of params.
	err = action.Execute(map[string]interface{}{
		"event_id": event.ID,
		"severity": event.Severity,
		"actor":    event.Actor,
	})

	if err != nil {
		return fmt.Errorf("action '%s' failed: %w", actionName, err)
	}

	return nil
}
