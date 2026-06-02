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
*   **Status:** Core Framework Complete.
*   **Implemented:**
    *   `Identity`: User, Session, and AuthResult structures.
    *   `AuthAuthority` Interface: The contract for all identity providers.
    *   `AuthRegistry`: A centralized registry to manage/route protocol adapters.
    *   `AuthAdapter` Types: Standardized types for protocol identification (LDAP, SAML, etc.).
    *   `MockAuthAdapter`: A testing implementation for rapid development and CI/CD.
    *   **Plugin Guide:** Documentation for building new protocol adapters.

### 2. Data Abstraction (`pkg/data`)
*   **Status:** Interface Initialized.
*   **Implemented:**
    *   `DataDriver` Interface: Defines `Connect`, `Execute`, and `Query`.
    *   `ResultIterator`: An abstraction to iterate over results without driver-specific leakage.

### 3. Security & Observability (SIEM/SOAR)
*   **Status:** Event Infrastructure Ready; Response Logic Pending.
*   **Implemented:**
    *   Event Dispatcher: A central hub for emitting security and system events.
    *   Audit Hooks: Mechanisms to intercept authentication attempts and log them.
*   **Pending:**
    *   Automated Response Plugins (The "SOAR" action layer).

---

## 📈 Completed Milestones
- [x] Established Go Portable Distribution (`go_dist`).
- [x] Implemented Identity & Authentication Layer (Auth Space).
- [x] Created Auth Protocol Registry and Adapter Interface.
- [x] Developed Mock Authentication for testing.
- [x] Initialized Data Driver/DAL Architecture.
/x] Published Plugin Development Documentation.

---

## 🗺 Roadmap & Next Steps

### Phase 1: Verification (Current)
- [ ] Implement a `SQLite` or `InMemory` `DataDriver` to test the DAL.
- [ ] Build out the first real `Auth Protocol Adapter` (e.g., LDAP/LDIF simulation).

### Phase 2: SOAR Expansion
- [ ] Create "Action Plugins" for automated response (e.g., a plugin that blocks an IP in the kernel's firewall list).
- [ ] Integrate the Event Dispatcher with external notification channels (Telegram, Email).

### Phase 3: Advanced Identity
- [ ] Implement SAML/OIDC support via external providers.
- [ ] Build out the O365 Graph API adapter.
