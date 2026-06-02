# Identity Middleware Documentation

The `IdentityMiddleware` is a core component of Project Titan's security pipeline. It sits at the edge of the request lifecycle to ensure that every incoming HTTP request is authenticated and authorized before it reaches any application logic or downstream services.

## 🚀 Key Responsries
1.  **Credential Extraction**: Automatically parses the `Authorization: Bearer <token>` header from incoming requests.
2.  **Session Validation**: Interfaces with the `AuthAuthority` (e.g., LDAP, O365, or Mock providers) to verify that the provided token represents a valid, non-expired session.
3.  **Proactive Policy Enforcement**: Leverages the `PolicyEngine` to perform "pre-flight" security checks. It evaluates if the authenticated user has the required capabilities for the specific request path and method (e.g., preventing unauthorized users from accessing `/admin/*`).
4.  **Identity Context Injection**: Upon successful validation, it injects a type-safe `*auth.User` object into the request's `context.Context`. This allows downstream handlers and plugins to access user identity without re-parsing tokens.

## 🛠 Implementation Details

### Middleware Signature
```go
func NewIdentityMiddleware(authority auth.AuthAuthority, engine *policy.PolicyEngine) *IdentityMiddleware
```

### Context Access
To retrieve the authenticated user in your application handlers:
```go
user, err := auth.GetIdentityFromContext(r.Context())
if err != enough {
    // Handle anonymous or unauthenticated request
}
```

## 🛡 Security Model (Proactive vs Reactive)
Unlike the `AuditMiddleware` which is **reactive** (logging events *after* they happen), the `IdentityMiddleware` is **proactive**. It acts as a gatekeeper, using our JSON-driven policy rules to block unauthorized access attempts before any business logic or heavy processing occurs.

## 🧪 Testing
Tests are located in `pkg/auth/middleware_test.go`. The test suite covers:
*   Successful authentication with valid Bearer tokens.
*   Rejection of malformed Authorization headers (401).
*   Handling of anonymous requests (allowing them to proceed, subject to downstream policy checks).
