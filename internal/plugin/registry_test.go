// SPDX-License-Identifier: AGPL-3.0-or-later
package plugin

import (
	"context"
	"fmt"
	"testing"
)

// MockPlugin is a minimal implementation of the Plugin interface for testing purposes.
type MockPlugin struct {
	name        string
	initialized bool
}

func (m *MockPlugin) Name() string { return m.name }

func (m *MockPlugin) Initialize(ctx TitanContext) error {
	m.initialized = true
	return nil
}

func (m *MockPlugin) HandleRequest(ctx context.Context, ctxTitan TitanContext, requestData []byte) ([]byte, error) {
	if !m.initialized {
		return nil, fmt.Errorf("plugin not initialized")
	}
	return append([]byte("Processed: "), requestData...), nil
}

func (m *MockPlugin) Shutdown() error {
	m.initialized = false
	return nil
}

// TestContext implements TitanContext with no-op methods for testing.
type TestContext struct {
	TitanContext
}

func (t *TestContext) Log(message string, level string) {}
func (t *TestContext) GetHeader(name string) (string, bool) { return "", false }
func (t *TestContext) SetHeader(name, value string) {}
func (t *TestContext) GetConfig(key string) (interface{}, bool) { return nil, false }

func TestRegistry_Lifecycle(t *testing.T) {
	registry := NewRegistry()
	plugin := &MockPlugin{name: "test-plugin"}

	// 1. Test Register
	err := registry.Register(plugin)
	if err != nil {
		t.Fatalf("Failed to register plugin: %v", err)
	}

	// 2. Test Duplicate Registration (should fail)
	err = registry.Register(plugin)
	if err == nil {
		t.Error("Expected error when registering duplicate plugin, but got none")
	}

	// 3. Test Get
	retrieved, err := registry.Get("test-plugin")
	if err != nil {
		t.Fatalf("Failed to get plugin: %v", err)
	}
	if retrieved.Name() != "test-plugin" {
		t.Errorf("Expected plugin name 'test-plugin', got '%s'", retrieved.Name())
	}

	// 4. Test List
	list := registry.List()
	if len(list) != 1 || list[0] != "test-plugin" {
		t.Errorf("Unexpected list contents: %v", list)
	}

	// 5. Test Remove
	err = registry.Remove("test-plugin")
	if err != nil {
		t.Fatalf("Failed to remove plugin: %v", err)
	}

	// 6. Test Get after removal (should fail)
	_, err = registry.Get("test-plugin")
	if err == nil {
		t.Error("Expected error when getting removed plugin, but got none")
	}
	
	// 7. Verify List is empty
	if len(registry.List()) != 0 {
		t.Errorf("Expected empty list after removal, got %v", registry.List())
	}
}
