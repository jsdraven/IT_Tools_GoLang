// SPDX-License-Identifier: AGPL-3.0-or-later
package adapter

import (
	"context"
	"errors"
	"IT_Tools_GoLang_New/pkg/auth"
)

// MockAuthAdapter is a testing implementation of the AuthAdapter interface.
// It allows us to simulate successful and failed authentication without external dependencies.
type MockAuthAdapter struct {
	// Users maps username -> password for simulation
	Users map[string]string
}

// NewMockAuthAdapter creates a new instance of the mock adapter.
func NewMockAuthableAdapter(users map[string]string) *MockAuthAdapter {
	return &MockAuthAdapter{
		Users: users,
	}
}

// Authenticate simulates an authentication attempt against the internal user map.
func (m *MockAuthAdapter) Authenticate(ctx context.Context, credentials map[string]string) (*auth.AuthResult, error) {
	username := credentials["username"]
	password := credentials["password"]

	storedPassword, exists := m.Users[username]
	if !exists {
		return &auth.AuthResult{
			Success: false,
			Error:   "user not found",
		}, nil
	}

	if storedPassword != password {
		return &auth.AuthResult{
			Success: false,
			Error:   "invalid credentials",
		}, nil
	}

	// Simulate a successful user object return
	return &auth.AuthResult{
		Success: true,
		User: &auth.User{
			ID:       "mock-id-" + username,
			Username: username,
			Role:     "admin", // Defaulting to admin for testing ease
		},
	}, nil
}

// ValidateSession simulates session validation.
func (m *MockAuthAdapter) ValidateSession(ctx context.Context, token string) (*auth.User, error) {
	if token == "valid-token" {
		return &auth.User{
			ID:       "mock-id-admin",
			Username: "admin",
			Role:     "admin",
		}, nil
	}
	return nil, errors.New("invalid session token")
}

// Logout simulates logging out.
func (m *MockAuthAdapter) Logout(ctx context.Context, token string) error {
	return nil
}
