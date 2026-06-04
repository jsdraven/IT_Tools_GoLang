// SPDX-License-Identifier: AGPL-3.0-or-later
package auth

import (
	"errors"
	"sync"
	"time"

	"github.com/google/uuid"
)

// Manager handles user authentication and session lifecycle.
type Manager struct {
	mu       sync.RWMutex
	users    map[string]*User     // Username -> User
	sessions map[string]*Session  // Token -> Session
}

// NewManager initializes a new Authentication Manager.
func NewManager() *Manager {
	return &Manager{
		users:    make(map[string]*User),
		sessions: make(map[string]*Session),
	}
}

// RegisterUser adds a new user to the system (for demo/setup purposes).
func (m *Manager) RegisterUser(username, passwordHash, role string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.users[username]; exists {
		return errors.New("user already exists")
	}

	m.users[username] = &User{
		ID:           uuid.New().String(),
		Username:     username,
		PasswordHash: passwordHash,
		Role:         role,
		CreatedAt:    time.Now(),
	}
	return nil
}

	// Authenticate verifies credentials and returns a session token if successful.
func (m *Manager) Authenticate(username, passwordAttempt string) (*AuthResult, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	user, exists := m.users[username]
	if !exists || user.PasswordHash != passwordAttempt { // In production, use bcrypt/argon2
		return &AuthResult{Success: false, Error: "invalid credentials"}, nil
	}

	// Create a new session
	token := uuid.New().String()
	session := &Session{
		Token:     token,
		UserID:    user.ID, // Fixed: was int64 in struct but string in logic
		ExpiresAt: time.Now().Add(24 * time.Hour),
		CreatedAt: time.Now(),
	}
	m.sessions[token] = session

	return &AuthResult{Success: true, User: user}, nil
}

// ValidateSession checks if a token is valid and not expired.
func (m *Manager) ValidateSession(token string) (*User, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	session, exists := m.sessions[token]
	if !exists {
		return nil, errors.New("session not found")
	}

	if time.Now().After(session.ExpiresAt) {
		return nil, errors.New("session expired")
	}

	// Find the user associated with this session
	for _, user := range m.users {
		if user.ID == session.UserID {
			return user, nil
		}
	}

	return nil, errors.New("user not found for session")
}

// Logout invalidates a session token.
func (m *Manager) Logout(token string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.sessions, token)
}
