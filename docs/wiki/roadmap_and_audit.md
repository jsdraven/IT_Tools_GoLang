# Project Titan: Roadmap & RBAC Analysis

## 🗺 Roadmap

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

---

## 🔍 RBAC Implementation Gap Analysis (Audit: June 2026)

The following gaps were identified during a recent audit of the Role-Based Access Control implementation:

* **Identity Gaps**: The `User` struct relies on string-based roles; it lacks formal `Role` and `Permission` entities.
* **Logic Gaps**: While an `AuthAuthority` interface exists, the evaluation engine is not yet implemented within a local provider.
* **Enforcement Gaps**: The system needs integration with the new structured RBAC decision engine to ensure consistent enforcement across all adapters.
