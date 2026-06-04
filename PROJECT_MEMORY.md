# Project Titan: Core Memory & Progress Log

## 🎯 Project Vision
Project Titan is a high-performance, plugin-oriented system designed with a **Kernel/Plugin architecture**. The goal is to create a platform engine that decouples core logic from external services (Data Warehousing, Identity Providers, and Security Orchestration).

### Key Architectural Pillars:
1.  **Identity-as-a-Service (IDaaS):** A decoupled Auth Space where the Kernel acts as a Service Provider/Relying Party, delegating authentication to specialized Protocol Adapters (SAML, LDAP, O365).
2.  **Data Abstraction Layer (DAL):** A database-agnostic layer where the Kernel interacts with a `DataDriver` interface, shielding applications from underlying SQL dialects (Postgres, MySQL, MSSQL).
3.  **SIEM/SOAR Capability:** An event-driven nervous system that intercepts security events (Audit Logs) and provides the framework for automated response via plugins.

---

## 🛠 Current Architectural State

### 1. Authentication & Identity (`pkg/auth`)
*   **Status:** Core Framework Complete; **"Titan-Secure" Local Auth implemented.**
*   **Implemented:**
    *   `Identity`: User (with RBCT Support), Session, and AuthResult structures.
    *   `AuthAuthority` Interface: The contract for all identity providers.
    *   `AuthRegistry`: A centralized registry to manage/route protocol adapters.
    *   **"Titan-Secure" Local Adapter**: High-complexity standalone provider with Argon2id readiness, Bootstrap Lockdown (mandatory password rotation), and RBAC (Site vs Server roles).
    *   **Policy Engine**: Built-in enforcement of password complexity and pattern prevention.
    *   `IdentityMiddleware`: Proactive interception of requests for token extraction and policy enforcement.
    *   `MockAuthAdapter`: A testing implementation for rapid development and CI/SS.
    *   **Plugin Guide:** Documentation for building new protocol adapters.
    *   **Integration Tests (Pending Verification)**: Test suite for "Bootstrap Lockdown" and RBAC isolation.

### 2. Data Abstraction (`pkg/data`)
*   **Status:** Interface Initialized.
*   **Implemented:**
    *   `DataDriver` Interface: Defines `Connect`, `Execute`, and `Query`.
    *   `ResultIterator`: An abstraction to iterate over results without driver-specific leakage.

### 3. Security & Observability (SIEM/SOAR)
*   **Status:** Event Infrastructure Ready; Response Logic Implemented via Tiered Orchestration.
*   **Implemented:**
    *   Event Dispatcher: A central hub for emitting security and system events.
    *   Audit Hooks: Mechanisms to intercept authentication attempts and log them.
    *   **Tiered Event Orchestration**: A high-performance pipeline using a Triage layer (O(1) routing) with an automated fallback to a JSON-driven Policy Engine.
    *   **Action Registry & Plugins**: Framework for executing actions via plugins (e.g., `LoggingActionPlugin`, `SpyAction`).
    *   **Capability-Based Security**: Implementation of `TitanContext` to sandbox plugin execution.
*   **Pending:**
    *   Automated Response Plugins (The "SOAR" action layer) expansion.
    *   Integrate the Event Dispatcher with external notification channels (Telegram, Email).

---

## 📈 Completed Milestones
- [x] Established Go Portable Distribution (`go_dist`).
- [x] Implemented Identity & Authentication Layer (Auth Space).
- [x] Created Auth Protocol Registry and Adapter Interface.
- [x] Developed Mock Authentication for testing.
- [x] Initialized Data Driver/DAL Architecture.
- [x] Implemented JSON-driven Policy Engine with Predicate Registry.
- [x] Established Plugin Interface with `TitanContext` capability-based security.
- [x] Implemented Tiered Event Orchestration (Triage $\rightarrow$ Policy Engine).
- [x] Published Plugin Development Documentation.

---

## 🗺 Roadmap & Next Steps

## 🗺 Roadmap & Next Steps

### Phase 1: Verification (Current)
- [ ] Implement a `SQLite` or `InMemory` `DataDriver` to test the DAL.
- [ ] Build out the first real `Auth Protocol Adapter` (e.g., LDAP/LDIF simulation).

### Phase 2: SOAR Expansion & Identity Middleware
- [x] Implement **Identity Middleware** to intercept requests and apply policy/auth checks.
- [ ] Create "Action Plugins" for automated response expansion.
- [ ] Integrate the Event Dispatcher with external notification channels (Telegram, Email).

### Phase 3: Advanced Identity & Wasm Isolation
- [ ] Implement SAML/OIDC support via external providers.
- [ ] Build out the O365 Graph API adapter.
- [ ] Implement **Wasm-based isolation** for the plugin system to enhance security.


### RBAC Implementation Gap Analysis (Audit Completed June 2026)
* **Identity Gaps**:  struct relies on string-based roles (); lacks formal  and  entities.
* **Logic Gaps**:  interface exists, but the evaluation engine is not yet implemented in a local provider.
* **Enforcement Gaps**:  needs integration with the new structured RBAC decision engine.
