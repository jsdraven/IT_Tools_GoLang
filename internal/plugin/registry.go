// SPDX-License-Identifier: AGPL-3.0-or-later
package plugin

import (
	"fmt"
	"sync"
)

// Registry manages the lifecycle and lookup of loaded plugins in the Kernel.
type Registry struct {
	plugins sync.Map // map[string]Plugin
}

// NewRegistry initializes a new Plugin Registry.
func NewRegistry() *Registry {
	return &Registry{}
}

// Register adds a plugin to the registry. 
// If a plugin with the same name already exists, it returns an error to prevent accidental overwrites.
func (r *Registry) Register(p Plugin) error {
	if p == nil {
		return fmt.Errorf("cannot register a nil plugin")
	}

	name := p.Name()
	if _, loaded := r.plugins.LoadOrStore(name, p); loaded {
		return fmt.Errorf("plugin with name '%s' is already registered", name)
	}

	return nil
}

// Get retrieves a plugin by its unique name.
func (r *Registry) Get(name string) (Plugin, error) {
	val, ok := r.plugins.Load(name)
	if !ok {
		return nil, fmt.Errorf("plugin '%s' not found", name)
	}

	return val.(Plugin), nil
}

// Remove unregisters a plugin from the registry.
func (r *Registry) Remove(name string) error {
	if _, ok := r.plugins.LoadAndDelete(name); !ok {
		return fmt.Errorf("cannot remove: plugin '%s' not found", name)
	}
	return nil
}

// List returns a slice of all currently registered plugin names.
func (r *Registry) List() []string {
	var names []string
	r.plugins.Range(func(key, value any) bool {
		names = append(names, key.(string))
		return true
	})
	return names
}
