// SPDX-License-Identifier: AGPL-3.0-or-later
package actions

import (
	"context"
)

// ActionDriver defines the contract that any automation plugin must implement.
// This allows the Kernel to execute orchestrated responses (e.g., blocking an IP,
// sending a notification, or revoking a session) without knowing the implementation.
type ActionDriver interface {
	// Name returns the unique identifier for this action driver (e.g., "firewall-block", "telegram-notify").
	Name() string

	// Execute performs the automation task using the provided parameters.
	// Parameters are passed as a map to allow for flexible, plugin-specific inputs.
	Execute(ctx context.Context, params map[string]interface{}) (*ActionResponse, error)
}

// ActionResponse encapsulates the result of an executed action.
type ActionResponse struct {
	// Success indicates if the action was completed without errors.
	Success bool `json:"success"`

	// Message provides a human-readable summary or error detail from the driver.
	Message string `json:"message"`

	// Metadata allows for returning arbitrary data from the execution (e.g., a new rule ID).
	Metadata map[string]interface{} `json:"metadata,omitempty"`
}
