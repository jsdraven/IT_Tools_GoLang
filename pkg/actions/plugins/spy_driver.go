// SPDX-License-Identifier: AGPL-3.0-or-later
package plugins

import (
	"context"
	"sync"
)

// SpyAction implements the ActionDriver interface for testing purposes.
// It records calls so that tests can assert against them.
type SpyAction struct {
	mu           sync.Mutex
	name         string
	CalledCount  int
	LastParams   map[string]interface{}
	ReturnResult map[string]interface{}
	ReturnError  error
}

// NewSpyAction initializes a new spy action driver.
func NewSpyAction(name string) *SpyAction {
	return &SpyAction{
		name: name,
	}
}

// Name returns the name of the action.
func (a *SpyAction) Name() string {
	return a.name
}

// Execute records the call and returns predefined results.
func (a *SpyAction) Execute(ctx context.Context, params map[string]interface{}) (map[string]interface{}, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	a.CalledCount++
	a.LastParams = params

	return a.ReturnResult, a.ReturnError
}

// SetResponse allows the test to control what the spy returns.
func (a *SpyAction) SetResponse(result map[string]interface{}, err error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.ReturnResult = result
	a.ReturnError = err
}

// GetStats returns the current call count and last params in a thread-safe way.
func (a *SpyAction) GetStats() (int, map[string]interface{}) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.CalledCount, a.LastParams
}
