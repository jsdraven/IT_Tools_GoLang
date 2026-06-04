# Data Abstraction & Security (SIEM/SOAR)

## 📊 Data Abstraction Layer (DAL)
The `pkg/data` layer provides a database-agnostic interface to shield applications from underlying SQL dialects.

### Key Components
* **DataDriver Interface**: Defines the core contract with `Connect`, `Execute`, and `Query` methods.
* **ResultIterator**: An abstraction to iterate over results without driver-specific leakage.
* **Current Status**: Interface initialized; implementation of `SQLite` or `InMemory` drivers is pending for verification.

## 🛡 Security & Observability (SIEM/SOAR)
An event-driven "nervous system" designed for intercepting security events and automating responses.

### Event Infrastructure
* **Event Dispatcher**: A central hub for emitting security and system events.
* **Audit Hooks**: Mechanisms to intercept authentication attempts and log them.
* **Tiered Event Orchestration**: A high-performance pipeline using a **Triage layer (O(1) routing)** with an automated fallback to a JSON-driven Policy Engine.

### Response & Action Framework
* **Action Registry & Plugins**: Framework for executing actions via plugins (e.g., `LoggingActionPlugin`, `SpyAction`).
* **Capability-Based Security**: Implementation of `TitanContext` to sandbox plugin execution and limit blast radius.

### Roadmap
* Expansion of the "SOAR" action layer with more automated response plugins.
* Integration of the Event Dispatcher with external notification channels (Telegram, Email).
