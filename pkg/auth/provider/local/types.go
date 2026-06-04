// SPDX-License-Identifier: AGPL-3.0-or-later
package local

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// ProvisioningState represents the lifecycle state of the local authentication system.
type ProvisioningState string

const (
	StateBootstrapRequired ProvisioningState = "BOOTSTRAP_REQUIRED" // Initial boot, must change password
	StateActive             ProvisioningState = "ACTIVE"             // System is fully operational
	StateLocked             ProvisioningState = "LOCKED"             // Maintenance or security lockdown
)

// PasswordPolicy defines the constraints for local user passwords.
type PasswordPolicy struct {
	MinLength       int      `json:"min_length"`
	RequireSymbols  bool     `json:true"`
	RequireNumbers  bool     `json:"require_numbers"`
	RequireUppercase bool    `json:"require_uppercase"`
	AllowedPatterns []string `json:"allowed_patterns,omitempty"`
}

// LocalUser represents the internal storage model for a local user.
type LocalUser struct {
	ID                string            `json:"id"`
	Username          string            `json:"username"`
	PasswordHash      string            `json:"password_hash"` // Argon2id hash
	Roles             []string          `json:"roles"`         // e.g., ["server", "site:marketing"]
	Attributes        map[string]string `json:"attributes"`
	LastPasswordChange time.Time         `json:"last_password_change"`
	MustChangePassword bool              `json:"must_change_password"`
	CreatedAt         time.Time         `json:"created_at"`
}

// LocalAuthStore defines the interface for the underlying persistence layer.
type LocalAuthStore interface {
	GetUser(ctx context.Context, username string) (*LocalUser, error)
	SaveUser(ctx context.Context, user *LocalUser) error
	SetProvisioningState(ctx context.Context, state ProvisioningState) error
	GetProvisioningState(ctx context.Context) (ProvisioningState, error)
}

// AccessRequest represents a check to see if a specific role/permission is held.
type AccessRequest struct {
	UserID   string
	Resource string // e.g., "site:marketing" or "server:admin"
	Action   string // e.g., "read", "write", "manage"
}

// ValidationError represents a failure in policy enforcement.
type ValidationError struct {
	Field   string
	Reason  string
	Message string
}

func (e *ValidationError) Error() string {
	return fmt.Sprintf("validation failed on %s: %s (%s)", e.Field, e.Reason, e.Message)
}
