// SPDX-License-Identifier: AGPL-3.0-or-later
package local

import (
	"context"
	"errors"
	"sync"
	"time"
)

// InMemoryAuthStore is a simple thread-safe in-memory implementation of LocalAuthStore.
type InMemoryAuthStore struct {
	mu                sync.RWMutex
	users             map[string]*LocalUser
	provisioningState ProvisioningState
}

// NewInMemoryAuthStore initializes a new in-memory store in Bootstrap mode.
func NewInMemoryAuthStore() *InMemoryAuthStore {
	return &InMemoryAuthStore{
		users:             make(map[string]*LocalUser),
		provisioningState: StateBootstrapRequired,
	}
}

func (s *InMemoryAuthStore) GetUser(ctx context.Context, username string) (*LocalUser, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	user, ok := s.users[username]
	if !ok {
		return nil, errors.New("user not found")
	}
	return user, nil
}

func (s *InMemoryAuthStore) SaveUser(ctx context.Context, user *LocalUser) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.users[user.Username] = user
	return nil
}

func (s *InMemoryAuthStore) SetProvisioningState(ctx context.Context, state ProvisioningState) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.provisioningState = state
	return nil
}

func (s *InMemoryAuthStore) GetProvisioningState(ctx context.Context) (ProvisioningState, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.provisioningState, nil
}
