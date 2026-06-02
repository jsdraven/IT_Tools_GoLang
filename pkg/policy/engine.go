// SPDX-License-Identifier: AGPL-3.0-or-later
package policy

import (
	"context"
	"fmt"
	"IT_Tools_GoLang_New/pkg/actions"
	"IT_Tools_GoLang_New/pkg/events"
	"IT_Tools_GoLang_New/pkg/config"
)

// PredicateFunc is a function that evaluates an event.
type PredicateFunc func(events.AuditEvent) bool

// Rule defines a condition that, when met by an event, triggers an action.
type Rule struct {
	ID          string                 `json:"id"`
	EventType   string                 `json:"event_type"` // Matches AuditEvent.Type
	Condition   PredicateFunc          `json:"-"`           // The logic to evaluate the event
	ActionName  string                 `json:"action_name"` // The name of the action in ActionRegistry
	ActionParam map[string]interface{} `json:"action_params"`
}

// PolicyEngine evaluates incoming events against a set of rules and triggers actions.
type PolicyEngine struct {
	rules      []Rule
	actions    *actions.ActionRegistry
	events     *events.InMemoryDispatcher
	predicates map[string]PredicateFunc
}

// NewPolicyEngine initializes a new engine with a registry of predicates.
func NewPolicyEngine(dispatcher *events.InMemoryDispatcher, actionRegistry *actions.ActionRegistry) *PolicyEngine {
	engine := &PolicyEngine{
		rules:      make([]Rule, 0),
		actions:    actionRegistry,
		events:     dispatcher,
		predicates: make(map[string]PredicateFunc),
	}

	// Subscribe the engine to the dispatcher so it hears all events.
	dispatcher.Subscribe(engine.Evaluate)

	return engine
}

// RegisterPredicate maps a string key (from JSON) to a Go condition function.
func (e *PolicyEngine) RegisterPredicate(name string, fn PredicateFunc) {
	e.predicates[name] = fn
}

// AddRule registers a new security rule in the engine.
func (e *PolicyEngine) AddRule(rule Rule) {
	e.rules = append(e.rules, rule)
}

// LoadRulesFromConfig reads rules from a JSON configuration file and hydrates them into the engine.
func (e *PolicyEngine) LoadRulesFromConfig(path string) error {
	cfg, err := config.LoadPolicyConfig(path)
	if err != nil {
		return fmt.Errorf("failed to load policy config: %w", err)
	}

	for _, rc := range cfg.Rules {
		rule := Rule{
			ID:          rc.ID,
			EventType:   rc.EventType,
			ActionName:  rc.ActionName,
			ActionParam: rc.ActionParams,
		}

		// Resolve the predicate from our registry.
		if rc.ConditionPredicate != "" {
			if fn, ok := e.predicates[rc.ConditionPredicate]; ok {
				rule.Condition = fn
			} else {
				return fmt.Errorf("predicate not found: %s", rc.ConditionPredicate)
			}
		}

		e.AddRule(rule)
	}

	return nil
}

// Evaluate is the core loop: it checks an event against all rules and triggers actions.
func (e *PolicyEngine) Evaluate(event events.AuditEvent) {
	for _, rule := range e.rules {
		// 1. Check if the event type matches the rule's interest.
		if rule.EventType == string(event.Type) {

			// 2. Evaluate the custom condition logic (predicate).
			// If no predicate is provided or it fails, we skip the action.
			if rule.Condition != nil && !rule.Condition(event) {
				continue
			}

			// 3. Trigger the action via the ActionRegistry.
			action, err := e.actions.GetAction(rule.ActionName)
			if err != nil {
				return
			}

			// Execute asynchronously so the Dispatcher doesn't block on long-running actions.
			go func(a actions.ActionDriver, r Rule) {
				_, _ = a.Execute(context.Background(), r.ActionParam)
			}(action, rule)
		}
	}
}
