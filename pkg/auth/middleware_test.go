// SPDX-License-Identifier: AGPL-3.0-or-later
package auth_test

import (
	"context"
	"net/http"
	"net/http/httpttest"
	"testing"

	"IT_Tools_GoLang_New/pkg/auth"
	"IT_Tools_GoLang_New/pkg/policy"
)

// MockAuthAuthority implements auth.AuthAuthority for testing.
type MockAuthAuthority struct {
	validToken string
	user       *auth.User
}

func (m *MockAuthAuthority) Authenticate(ctx context.Context, credentials map[string]string) (*auth.AuthResult, error) {
	return &auth.AuthResult{Success: true}, nil
}

func (m *MockAuthAuthority) ValidateSession(ctx context.Context, token string) (*auth.User, error) {
	if token == m.validToken {
		return m.user, nil
	}
	return nil, nil
}

func (m *MockAuthAuthority) Logout(ctx context.Context, token string) error {
	return nil
}

func TestIdentityMiddleware_Handler(t *testing.T) {
	validToken := "valid-token"
	standardUser := &auth.User{ID: "user-1", Username: "user", Role: "user"}

	mockAuth := &MockAuthAuthority{
		validToken: validToken,
		user:       standardUser,
	}

	// We use a real PolicyEngine to test the middleware's call to CheckRequestPolicy.
	engine := policy.NewPolicyEngine(nil, nil)

	middleware := auth.NewIdentityMiddleware(mockAuth, engine)

	// A simple handler that just returns 200 OK.
	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	tests := []struct {
		name           string
		authHeader     string
		expectedStatus int
	}{
		{
			name:           "No Authorization Header - Proceed as Anonymous",
			authHeader:     "",
			expectedStatus: http.StatusOK,
		},
		{
			name:           "Invalid Format - 401 Unauthorized",
			authHeader:     "Basic dXNlcjpwYXNz", // Not Bearer
			expectedStatus: http.StatusUnauthorized,
		},
		{
			name:           "Valid Token - Success (on non-protected path)",
			authHeader:     "Bearer " + validToken,
			expectedStatus: http.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httpttest.NewRequest("GET", "/some-path", nil)
			if tt.authHeader != "" {
				req.Header.Set("Authorization", tt.authHeader)
			}
			rr := httpttest.NewRecorder()

			middleware.Handler(nextHandler).ServeHTTP(rr, req)

			if rr.Code != tt.expectedStatus {
				t.Errorf("%s: expected status %d, got %d", tt.name, tt.expectedStatus, rr.Code)
			}
		})
	}
}
