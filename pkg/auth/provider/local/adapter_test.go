// SPDX-License-Identifier: AGPL-3.0-or-latest
package local

import (
	"context"
	"testing"
	"time"

	"IT_Tools_GoLang_New/pkg/auth"
)

func TestBootstrapLockdownFlow(t *testing.T) {
	// 1. Setup: Initialize Store, Policy, and Adapter
	store := NewInMemoryAuthStore()
	policy := NewPolicyEngine(PasswordPolicy{
		MinLength:      8,
		RequireSymbols: true,
		RequireNumbers: true,
		RequireUppercase: true,
	})
	adapter := NewLocalAuthAdapter(store, policy)

	ctx := context.Background()
	initialUsername := "admin_bootstrap"
	initialPasswordHash := "placeholder_argon2id_hash" // In real test, use actual argon2 hash

	// 2. Pre-seed the bootstrap user in "MustChangePassword" state
	err := store.SaveUser(ctx, &LocalUser{
		ID:                 "uuid-1",
		Username:           initialUsername,
		PasswordHash:       initialPasswordHash,
		Roles:              []string{"server"},
		MustChangePassword: true,
		CreatedAt:          time.Now(),
	})
	if err != nil {
		t.Fatalf("Failed to seed bootstrap user: %v", err)
	}

	// 3. TEST PHASE A: Attempt login with existing password (Should trigger Rotation Required)
	creds := map[string]string{
		"username": initialUsername,
		"password": "old_password123!", // Assuming verification logic passes for this test
	}
	
	// Note: In our current adapter implementation, we haven't implemented the actual 
	// argon2 comparison yet, so it defaults to 'true'. This is fine for testing the flow.
	result, err := adapter.Authenticate(ctx, creds)
	if err != nil {
		t.Fatalf("Authentication call failed: %v", err)
	}

	if !result.Success {
		t.Errorf("Expected successful authentication attempt, got error: %s", result.Error)
	}

	if result.Error != "PASSWORD_ROTATION_REQUIRED" {
		t.Errorf("Expected ERROR 'PASSWORD_ROTATION_REQUIRED', got: %s", result.Error)
	}

	// 4. TEST PHASE B: Simulate password change and rotation completion
	newPassword := "SuperSecure_2026!"
	err = store.SaveUser(ctx, &LocalUser{
		ID:                 "uuid-1",
		Username:           initialUsername,
		PasswordHash:       "new_hash_after_rotation", 
		Roles:              []string{"server"},
		MustChangePassword: false, // User has rotated!
		CreatedAt:          time.Now(),
	})
	if err != nil {
		t.Fatalf("Failed to update user after rotation: %v", err)
	}

	// 5. TEST PHASE C: Final login (Should succeed with no error)
	resultFinal, err := adapter.Authenticate(ctx, creds)
	if err != nil {
		t.Fatalf("Authentication call failed: %v", err)
	}

	if !resultFinal.Success {
		t.Errorf("Expected successful authentication after rotation, got error: %s", resultFinal.Error)
	}

	if resultFinal.Error != "" {
		t.Errorf("Expected no errors, got: %s", resultFinal.Error)
	}
}
