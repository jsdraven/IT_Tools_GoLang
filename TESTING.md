# Project Testing Strategy: Titan Engine

This document outlines the architectural approach and practical implementation of testing within Project Titan. Our strategy focuses on high-fidelity integration testing to verify the complex, asynchronous interactions between the Identity (Auth), Data (DAL), and Action (SOAR) pillars.

## Core Philosophy
We do not just test if code runs; we test if **policies are enforced**. Since the system is event-driven and asynchronous, traditional unit tests are insufficient. We prioritize **Integration Smoke Tests** that simulate real security events and verify the resulting automation traces.

## Key Components

### 1. The Event Pipeline (Sense $\rightarrow$ Act)
Testing follows the flow of an `AuditEvent`:
1.  **Dispatch**: A test event is injected into the `InMemoryDispatcher`.
2.  **Evaluation**: The `PolicyEngine` intercepts the event and evaluates it against registered `Rules`.
3.  **Execution**: The `ActionRegistry` retrieves the correct `ActionDriver` and executes it in a background goroutine.

###  $\rightarrow$ Verification via SpyAction
To verify asynchronous actions without relying on fragile log-scraping, we use the **`SpyAction`** pattern.

#### How to use `SpyAction` in a test:
The `SpyAction` is a programmable "black box" that records all interactions.

1.  **Initialize**: Create a spy with `plugins.NewSpyAction("test-driver")`.
2.  **Register**: Add the spy to your `ActionRegistry`.
3.  **Define Rule**: Create a `PolicyRule` that targets `"test-driver"`.
4.  **Inject Event**: Dispatch an event that triggers the rule.
5.  **Assert**: 
    *   Use `GetStats()` to verify `CalledCount` increased.
    *   Inspect `LastParams` to ensure the payload (e.g., UserID, IP) was correctly mapped from the event to the action parameters.

### 2. Error Injection Testing
The `SpyAction` allows us to simulate infrastructure failures. By using `.SetResponse(nil, errors.New("network timeout"))`, we can test if the `PolicyEngine` gracefully handles failed actions without crashing the entire dispatching loop.

## Running Tests
All tests are part of the standard Go toolchain. Use the following command from the project root:

```bash
go test ./...
```

For verbose output (useful for debugging failed assertions):
```bash
go test -v ./...
```

## Testing Checklist for New Features
- [ ] **Unit Test**: Does the new logic work in isolation?
- [ ] **Integration Test**: If an event occurs, does the `PolicyEngine` see it?
- [ ] **Action Trace**: Using `SpyAction`, can we verify the correct `ActionDriver` was called with the expected parameters?
- [ ] **Failure Mode**: Does the system survive if this new component returns an error?
