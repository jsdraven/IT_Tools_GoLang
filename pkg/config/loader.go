// SPDX-License-Identifier: AGPL-3.0-or-later
package config

import (
	"encoding/json"
	"fmt"
	"os"
)

// PolicyConfig represents the root structure of our policy JSON file.
type PolicyConfig struct {
	Rules []RuleConfig `json:"rules"`
}

// RuleConfig defines the serializable part of a Rule.
// We use 'condition_predicate' because functions cannot be serialized in JSON.
type RuleConfig struct {
	ID                string                 `json:"id"`
	EventType         string                 `json:"event_type"`
	ConditionPredicate string                 `json:"condition_predicate"`
	ActionName        string                 `json:"action_name"`
	ActionParams      map[string]interface{} `json:"action_params"`
}

// LoadPolicyConfig reads a JSON file from the given path and parses it.
func LoadPolicyConfig(path string) (*PolicyConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	var config PolicyConfig
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to unmarshal JSON: %w", err)
	}

	return &config, nil
}
