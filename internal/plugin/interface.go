// SPDX-License-Identifier: AGPL-3.0-or-later
package plugin

import (
	"context"
)

// TitanContext defines the capabilities injected into a plugin during execution.
// This implements the "Capability-Based Security" pillar of Project Titan.
type TitanContext interface {
	// Log sends a structured log message from the plugin to the Kernel's logger.
	Log(message string, level string)

	// GetHeader retrieves a specific request header for the current transaction.
	GetHeader(name string) (string, bool)

	// SetHeader allows a plugin to modify or add headers to the outgoing response.
	SetHeader(name, value string)

	// GetConfig retrieves a configuration parameter from the global JSON config.
	GetConfig(key string) (interface{}, bool)
}

// Plugin defines the lifecycle and execution interface for all Titan plugins.
// Whether it is a Wasm module or a sidecar process, it must satisfy this contract.
type Plugin interface {
	// Name returns the unique identifier of the plugin.
	Name() string

	// Initialize is called once when the plugin is loaded into the Kernel.
	// It allows the plugin to set up its internal state and dependencies.
	Initialize(ctx TitanContext) error

	// HandleRequest is the primary execution hook. 
	// The Kernel calls this whenever a request matches the plugin's registered extension or route.
	HandleRequest(ctx context.Context, ctxTitan TitanContext, requestData []byte) ([]byte, error)

	// Shutdown is called during a graceful reload or when the plugin is removed.
	Shutdown() error
}
