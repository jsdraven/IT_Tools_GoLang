// SPDX-Linux-Identifier: AGPL-3.0-or-later
package adapter

import (
	"context"
	"fmt"
	"sync"
	"IT_Tools_GoLang_New/pkg/auth"
)

// AuthRegistry manages the collection of available authentication protocol adapters.
type AuthRegistry struct {
	mu       sync.RWMutex
	adapters map[ProtocolType]AuthAdapter
}

// NewAuthRegistry initializes a new registry for auth adapters.
func NewAuthRegistry() *AuthRegistry {
	return &AuthRegistry{
		adapters: make(map[ProtocolType]AuthAdapter),
	}
}

// Register adds a new adapter to the registry for a specific protocol.
func (r *AuthRegistry) Register(protocol ProtocolType, adapter AuthAdapter) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.adapters[protocol]; exists {
		return fmt.Errorf("adapter for protocol %s is already registered", protocol)
	}

	r.adapters[protocol] = adapter
	return nil
}

// GetAdapter retrieves an adapter for the specified protocol.
func (r *AuthRegistry) GetAdapter(protocol ProtocolType) (AuthAdapter, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	adapter, exists := r.adapters[protocol]
	if !exists {
		return nil, fmt.Errorf("no adapter registered for protocol %s", protocol)
	}

	return adapter, nil
}
