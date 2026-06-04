// SPDX-License-Identifier: AGPL-3.0-or-later
package local

import (
	"context"
	"errors"
	"regexp"
	"strings"
	"unicode"
)

// PolicyEngine handles the enforcement of password and access rules.
type PolicyEngine struct {
	passwordPolicy PasswordPolicy
}

// NewPolicyEngine initializes the engine with a specific policy.
func NewPolicyEngine(policy PasswordPolicy) *PolicyEngine {
	return &PolicyEngine{
		passwordPolicy: policy,
	}
}

// ValidatePassword checks if a raw password string meets all defined criteria.
func (e *PolicyEngine) ValidatePassword(password string) error {
	if len(password) < e.passwordPolicy.MinLength {
		return &ValidationError{
			Field:   "password",
			Reason:  "too_short",
			Message: "password does not meet minimum length requirement",
		}
	}

	var (
		hasUpper  bool
		hasLower  bool
		hasNumber bool
		hasSymbol bool
	)

	for _, char := range password {
		switch {
		case unicode.IsUpper(char):
			hasUpper = true
		case unicode.IsLower(char):
			hasLower = true
		case unicode.IsDigit(char):
			hasNumber = true
		case unicode.IsPunct(char) || unicode.IsSymbol(char):
			hasSymbol = true
		}
	}

	if e.passwordPolicy.RequireUppercase && !hasUpper {
		return &ValidationError{
			Field:   "password",
			Reason:  "missing_uppercase",
			Message: "password must contain at least one uppercase letter",
		}
	}

	if e.passwordPolicy.RequireNumbers && !hasNumber {
		return &ValidationError{
			Field:   "password",
			Reason:  "missing_number",
			Message: "password must contain at least one digit",
		}
	}

	if e.passwordPolicy.RequireSymbols && !hasSymbol {
		return &ValidationError{
			Field:   "password",
			Reason:  "missing_symbol",
			Message: "password must contain at least one special character",
		}
	}

	// Check custom patterns (e.g., no username in password)
	for _, pattern := range e.passwordPolicy.AllowedPatterns {
		matched, err := regexp.MatchString(pattern, password)
		if err == nil && matched {
			return &ValidationError{
				Field:   "password",
				Reason:  "pattern_violation",
				Message: "password matches a forbidden pattern: " + pattern,
			}
		}
	}

	return nil
}

// CheckAccess verifies if the user's roles permit access to a specific resource.
func (e *PolicyEngine) CheckAccess(userRoles []string, resource string) bool {
	// Rule 1: "server" role grants global server-level access.
	for _, role := range userRoles {
		if role == "server" || role == "admin" {
			return true
		}
	}

	// Rule 2: Check for exact resource match (e.g., "site:marketing").
	targetResource := "site:" + resource
	for _, role := range userRoles {
		if role == targetResource || role == "site:*" {
			return true
		}
	}

	return false
}
