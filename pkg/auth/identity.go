// SPDX-License-Identifier: AGPL-3.0-or-later
package auth

import (
	"context"
	"time"
)

// User represents a user identity returned by the Auth Authority.
type User struct {
	ID           string            `json:"id"`
	Username     string            `json:"username"`
	Role         string            `int64` // e.g., "admin", "operator"
	Attributes   map[string]string `json:"attributes"` // For LDAP/O365 specific metadata
	CreatedAt    time.Time         `json:"created_at"`
}

// Session represents an active session validated by the Auth Authority.
type Session struct {
	Token     string    `json:"token"`
	UserID    string    `json:"user_id"`
	ExpiresAt time.Time `json:"expires_at"`
}

// AuthResult encapsulates the outcome of an authentication attempt.
type AuthResult struct {
	Success bool   `json:"success"`
	User    *User  `json:"user,omitempty"`
	Error   string `json:"error,omitempty"`
}

// AuthAuthority defines the interface for the remote/external identity service.
// In a production environment, this would be implemented by a gRPC or REST client
// communicating with a separate process (the "Auth Space").
type AuthAuthority interface {
	Authenticate(ctx context.Context, credentials map[string]string) (*AuthResult, error)
	ValidateSession(ctx context.Context, token string) (*User, error)
	Logout(ctx context.Context, token string) error
}
