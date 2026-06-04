# Authentication & Identity (`pkg/auth`)

## 🛡 Overview
The authentication system is designed as a decoupled Auth Space where the Kernel acts as a Service Provider, delegating authentication to specialized Protocol Adapters.

## 🛠 Implemented Components

### Core Framework
* **Identity**: Includes `User` (with RBCT Support), `Session`, and `AuthResult` structures.
* **AuthAuthority Interface**: The contract that all identity providers must implement.
* **AuthRegistry**: A centralized registry to manage and route protocol adapters.

### "Titan-Secure" Local Adapter
A high-complexity standalone provider featuring:
* **Argon2id Readiness**: Secure password hashing.
* **Bootstrap Lockdown**: Mandatory password rotation upon first use.
* **RBAC (Role-Based Access Control)**: Supports `Site` vs `Server` roles.

### Security & Enforcement
* **Policy Engine**: Built-in enforcement of password complexity and pattern prevention.
* **IdentityMiddleware**: Proactive interception of requests for token extraction and policy enforcement.
* **MockAuthAdapter**: A testing implementation for rapid development and CI/CD.

## 🚀 Plugin Development
Documentation for building new protocol adapters can be found in the `auth_plugin_guide.md`.
