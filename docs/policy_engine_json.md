# 🧠 Policy Engine: JSON-Driven Configuration Guide

## Overview
The `PolicyEngine` has been upgraded from hardcoded Go rules to a dynamic, configuration-driven system. This allows for real-time policy updates without requiring a service restart or recompilation.

## Architecture: The "Brain" Upgrade
The engine uses a **Predicate-Action** pattern:
1.  **Event Arrival**: An `AuditEvent` is dispatched via the `InMemoryDispatcher`.
2.  **Rule Matching**: The engine iterates through loaded rules, filtering by `event_type`.
3.  **Predicate Evaluation**: For rules with complex logic, the engine looks up a pre-defined Go function (a **Predicate**) using a string identifier from the JSON config.
4.  **Action Execution**: If the condition is met, the engine retrieves the specified `action_name` from the `ActionRegistry` and executes it asynchronously.

## JSON Configuration Schema

The configuration file (e.g., `policies.json`) follows this structure:

| Field | Type | Description |
| :--- | :--- | :--- |
| `rules` | Array | A list of rule objects to be loaded. |
| `id` | String | Unique identifier for the rule. |
    | `event_type` | String | Must match an `events.AuditEventType` (e.g., `"Audit"`, `"Auth"`). |
    | `condition_predicate` | String | The key used to look up a Go function in the Engine's registry. Use `""` for "always true". |
    | `action_name` | String | The name of the registered action (e.g., `"logger"`, `"spy"`). |
    | `action_params` | Object | A JSON object containing parameters passed to the `ActionDriver.Execute()` method. |

### Example Configuration
```json
{
  "rules": [
    {
      "id": "rule-001",
      "event_type": "Audit",
      "condition_predicate": "severity_high",
      "action_name": "logger",
      "action_params": {
        "message": "CRITICAL: High severity audit event detected!"
	  }
    }
  ]
}
```

## Developer Guide

### 1. Registering a New Predicate (Go)
To support new complex logic in your JSON, you must register the predicate in your engine initialization code:

```go
engine.RegisterPredicate("severity_high", func(e events.AuditEvent) bool {
    // Logic to check event metadata for high severity
    return e.Metadata["severity"] == "high"
})
```

### 2. Loading Configuration
Use the `LoadRulesFromConfig` method on your engine instance:

```go
err := engine.LoadRulesFromConfig("path/to/policies.json")
if err != nil {
    log.Fatalf("Failed to upgrade Brain: %v", err)
}
```

## Security Considerations
* **Validation**: Always ensure `action_params` do not contain executable commands unless explicitly intended for a specific driver.
* **Path Integrity**: Ensure the path to the JSON config is protected by filesystem permissions to prevent unauthorized policy injection.
