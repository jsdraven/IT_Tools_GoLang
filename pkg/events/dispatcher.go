// SPDX-License-Identifier: AGPL-3.0-or-later
package events

import (
	"sync"
)

// InMemoryDispatcher is a simple implementation of EventDispatcher for development and testing.
type InMemoryDispatcher struct {
	mu          sync.RWMutex
	subscribers []func(AuditEvent)
}

// NewInMemoryDispatcher initializes a new dispatcher.
func NewInMemoryDispatcher() *InMemoryDispatcher {
	return &InMemoryDispatcher{
		subscribers: make([]func(AuditEvent), 0),
	}
}

// Dispatch sends the event to all registered subscribers.
func (d *InMemoryDispatcher) Dispatch(event AuditEvent) error {
	d.mu.RLock()
	defer d.mu.RUnlock()

	for _, handler := range d.subscribers {
		handler(event)
	}
	return nil
}

// Subscribe adds a new handler function to the list of subscribers.
func (d *InMemoryDispatcher) Subscribe(handler func(AuditEvent)) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.subscribers = append(d.subscribers, handler)
}
