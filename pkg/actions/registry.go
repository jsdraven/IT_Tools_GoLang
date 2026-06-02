// SPDX-License-Identifier: AGPL-3.0-or-later
package actions

import (
	"context"
	"fmt"
	"sync"
)

// ActionRegistry manages the collection of available automation plugins.
type ActionRegistry struct {
	mu       sync.RWMutex
	actions  map[string]ActionDriver
}

// NewActionRegistry initializes a new registry for action drivers.
func NewActionRegistry() *ActionRegistry {
	return &ActionRegistry{
		actions: make(map[string]ActionDriver),
	}
}

// Register adds an action driver to the registry.
func (r *ActionRegistry) Register(driver ActionDriver) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	name := driver.Name()
	if _, exists := r.actions[name]; exists {
		return fmt.Errorf("action driver with name %s is already registered", name)
	}

	r.actions[name] = driver
	return nil
}

// GetAction retrieves an action driver by its name.
func (r *ActionRegistry) GetAction(name string) (ActionDriver, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	driver, exists := r.actions[name]
	if !exists {
		return nil, fmt.Errorf("action driver %s not found", name)
	}

	return driver, nil
}
