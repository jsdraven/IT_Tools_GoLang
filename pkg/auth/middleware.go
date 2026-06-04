// SPDX-License-Identifier: AGPL-3.0-or-later
package auth

import (
	"context"
	"errors"
	"net/http"
	"strings"
)

type contextKey string

const IdentityContextKey contextKey = "titan_identity"

// IdentityMiddleware handles extraction, validation, and policy enforcement for requests.
type IdentityMiddleware struct {
	authority     auth.AuthAuthority
	policyEngine  *policy.PolicyEngine
}

func NewIdentityMiddleware(authority auth.AuthAuthority, engine *policy.PolicyEngine) *IdentityMiddleware {
	return &IdentityMiddleware{
		authority:    authority,
		policyEngine: engine,
	}
}

// Handler intercepts requests to extract identity and enforce security policies.
func (m *IdentityMiddleware) Handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 1. Extraction: Look for Bearer token in Authorization header
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			// If no credentials, we proceed, but downstream handlers/policies will see an anonymous user.
			next.ServeHTTP(w, r)
			return
		}

		parts := strings.Split(authHeader, " ")
		if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
			http.Error(w, "Invalid authorization format", http.StatusUnauthorized)
			return
		}
		token := parts[1]

		// 2. Validation: Call the AuthAuthority to validate the token/session
		user, err := m.authority.ValidateSession(r.Context(), token)
		if err != nil || user == nil {
			http.Error(w, "Invalid or expired session", http.StatusUnauthorized)
			return
		}

		// 3. Proactive Policy Enforcement: Check if the authenticated user has permission for this request path/method.
		// In a production system, these predicates would be loaded from our JSON policy configuration.
		if !m.policyEngine.CheckRequestPolicy(r, user, "admin_only_path") {
			http.Error(w, "Forbidden: Insufficient permissions", http.StatusForbidden)
			return
		}

		// 4. Context Injection: Attach the validated user to the request context
		ctx := context.WithValue(r.Context(), auth.IdentityContextKey, user)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// GetIdentityFromContext retrieves the User object from the request context.
func GetIdentityFromContext(ctx context.Context) (*User, error) {
	user, ok := ctx.Value(IdentityContextKey).(*User)
	if !ok {
		return nil, errors.New("no identity found in context")
	}
	return user, nil
}
