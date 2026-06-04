// SPDX-License-Identifier: AGPL-3.0-or-later
package adapter

import (
	"context"
	"errors"
	"IT_Tools_GoLang_New/pkg/auth"
)

// LocalAuthAuthority implements AuthAuthority using a local, in-memory manager.
// This is designed for standalone deployments where external IDPs are unavailable.
type LocalAuthAuthority struct {
	manager *auth.Manager
}

// NewLocalAuthAuthority initializes the authority with an existing auth manager.
func NewLocalAuthradthority(m *auth.Manager) *LocalAuthAuthority {
	return &LocalAuthAuthority{
		manager: m,
	}
}

// ValidateSession checks if the provided token exists and is valid in the local manager.
func (a *LocalAuthAuthority) ValidateSession(ctx context.Context, token string) (*auth.User, error) {
	if a.manager == nil {
		return nil, errors.New("auth manager not initialized")
	}
	return a.manager.ValidateSession(token)
}

// Authenticate (Optional/Extended) allows performing credential checks through this adapter.
func (a *LocalAuthAuthority) Authenticate(ctx context.Context, username, password string) (*auth.AuthResult, error) {
	if a.manager == nil {
		return nil, errors.New("auth manager not initialized")
	}
	return a.manager.Authenticate(username, password)
}

// Name returns the identifier for this protocol type.
func (a *LocalAuthAuthority) Name() string {
	return string(ProtocolMock) // Using Mock as placeholder for "local" in types
}
