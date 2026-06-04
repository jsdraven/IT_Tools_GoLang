# Plugin Development Guide: Authentication Adapters

This document outlines the architecture and process for building new authentication protocol adapters (e.g., SAML, LDAP, O365 Graph) for Project Titan's Kernel.

## 🏗 Architecture Overview

Project Titan uses a **Provider-Consumer** pattern to decouple identity management from application logic.

1.  **The Consumer (Web Site/Service):** Requests authentication via the `AuthAuthority` interface. It does not know *how* the user is authenticated, only that they *are* or *are not*.
2.  **The Kernel (Orchestrator):** Acts as the registry. It routes incoming auth requests to the correct protocol adapter based on configuration.
3.  **The Adapter (Plugin):** Implements the heavy lifting of communicating with external identity providers (IdPs).

## 🛠 How to Build a New Plugin

To create a new adapter, you must implement the `AuthAdapter` interface found in `pkg/auth/adapter/types.go`.

### 1. Define your Protocol
Add a new constant to `pkg/auth/adapter/types.go`:
```go
const ProtocolMyNewService ProtocolType = "my_new_service"
```

### 2. Implement the Interface
Create a new file in `pkg/auth/adapter/` (e.g., `my_new_service.go`) and implement these methods:

*   `Authenticate(ctx context.Context, credentials map[string]string) (*auth.AuthResult, error)`: The core logic. Use the `credentials` map to extract inputs (like username/password or OAuth codes) and return a standardized `AuthResult`.
*   `ValidateSession(ctx context.Context, token string) (*auth.User, error)`: Logic to verify if an existing session token is still valid.
*   `Logout(ctx context.Context, token string) error`: Handle session revocation or local cleanup.

### 3. Register the Plugin
During your application's initialization phase, register your new adapter with the `AuthRegistry`:

```go
registry := adapter.NewAuthRegistry()
myAdapter := mynewservice.NewAdapter(...)
registry.Register(adapter.ProtocolMyNewService, myAdapter)
```

## 🧬 Technical Details & Constraints

### Data Flow
1.  **Input:** Credentials arrive as a `map[string]string`. This allows for flexibility (one provider might need `username/password`, while another needs `client_id/secret`).
2.  **Output:** Always return an `*auth.AuthResult`. 
    *   If `Success: true`, you **must** provide a populated `*auth.User` object containing the user's ID and Roles.
3.  **Context Awareness:** You **MUST** respect the `context.Context` parameter. If the context is cancelled (e.g., the user closed their browser), your adapter must abort the network call to the IdP immediately to prevent resource leaks.

### Security Best Practices
*   **Zero Trust:** Never store raw passwords within the adapter's long-term state. 
*   **Error Sanitization:** When returning an `error` in `AuthResult`, do not leak sensitive backend details (like LDAP bind DNs or internal IP addresses) to the end-user. Log the detail internally, but return a generic "Authentication Failed" message.
*   **Memory Safety:** If your adapter handles sensitive tokens (JWTs, SAML assertions), ensure they are cleared from memory as soon as the `ValidateSession` call completes.

## 🧪 Testing
Use the existing `MockAuthAdapter` to test your Kernel's ability to route requests before implementing real network logic.
