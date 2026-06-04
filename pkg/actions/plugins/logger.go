// SPDX-License-Identifier: AGPL-3.0-or-later
package plugins

import (
	"context"
	"fmt"
	"log"
)

// LoggingAction implements the ActionDriver interface for simple logging purposes.
type LoggingAction struct {
	name string
}

// NewLoggingAction initializes a new logging action driver.
func NewLoggingAction() *LoggingAction {
	return &LoggingAction{
		name: "logger",
	}
}

// Name returns the name of the action.
func (a *LoggingAction) Name() string {
	return a.name
}

// Execute performs the logging action by printing parameters to the standard log.
func (a *LoggingAction) Execute(ctx context.Context, params map[string]interface{}) (map[string]interface{}, error) {
	message, ok := params["message"].(string)
	if !ok {
		message = "No message provided in action parameters."
	}

	log.Printf("[ACTION: %s] Executing with message: %s", a.name, message)

	return map[string]interface{}{
		"status":  "success",
		"message": "Logged: " + message,
	}, nil
}
