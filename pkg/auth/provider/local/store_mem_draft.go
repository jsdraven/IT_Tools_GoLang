// SPDX-License-Identifier: AGPL-3.0-or-later
package local

import (
	"context"
	"errors"
	"sync"
	"time"

	"IT_Tools_GoLang_New/pkg/auth"
)

// InMemoryAuthStore is a simple thread-safe in-memory implementation of LocalAuthStore.
type InMemoryAuthStore struct {
	mu               sync.RWMutex
	users            map[string]*LocalUser
	provisioningState ProvisioningState
}

func NewInMemoryAuthStore() *InMemoryAuthCRStore {
	return &InMemoryAuthStore{
		users:             make(map[string]*LocalUser),
		provisioningState: StateBootstrapRequired,
	}
}

// Note: I'll rename this to match the expected return type in the interface.
// Re-writing properly below.
