# Triage/Dispatcher Architecture Design

The **Triage Engine** is the high-performance routing core of Project Titan. Its goal is to achieve $O(1)$ complexity when deciding which action to take based on an incoming event, ensuring that as our system scales to thousands of rules and plugins, the latency remains constant.

## 🎯 Core Objective
Move away from "linear scanning" (looping through all rules) to "direct mapping" (looking up the correct handler immediately).

## 🏗️ Architecture: The "Map-Based Dispatch" Model

Instead of a list of rules that we iterate over, we will use a **multi-tiered dispatch table**.

### 1. The Event $\rightarrow$ Handler Map
We will maintain a `map[string]HandlerFunc` (or similar) where the key is a composite string representing the event's "Routing Key".

**The Routing Key Formula:**
`{EventType}:{ResourceID}:{ActionType}`
*Example:* `audit:user_login:deny`

### 2. The Dispatch Flow
1.  **Event Arrival**: An event (e.g., `AuditEvent`) enters the system.
2.  **Key Generation**: The Triage Engine extracts relevant metadata from the event to generate its unique Routing Key.
3.  **Direct Lookup**: The engine performs a single map lookup in the Dispatch Table.
4.  **Execution**:
    *   **Match Found**: Execute the mapped `ActionDriver` (from the Action Registry) immediately.
    *   **No Match**: Fall back to the **Policy Engine** for complex, condition-based evaluation (the "Safety Net").

## 🛠️ Implementation Components

### `pkg/triage/dispatcher.go`
The core engine containing:
- `DispatchTable`: The internal `sync.Map` or `map[string]ActionName`.
- `RegisterHandler(eventKey string, actionName string)`: To map keys to actions.
- `Dispatch(event *events.Event) error`: The primary entry point that performs the lookup and triggers execution.

### `pkg/triage/triage_test.go`
Testing the $O(1)$ path:
- Test direct match.
- Test "No Match" fallback to Policy Engine.
- Test performance (verifying constant time behavior with increasing rule counts).

## 🛡️ Safety & Fallback Strategy
The Triage Engine is **not** a replacement for the Policy Engine; it is an **accelerator**. 

- **Tier 1: Triage (Fast Path)**: Handles known, high-frequency, deterministic patterns (e.g., "If event is X, always do Y").
- **Tier 2: Policy Engine (Deep Inspection Path)**: Handles complex, context-aware logic (e.g., "If event is X AND user is from Region Y AND time is between Z").

If the Triage lookup fails, we *must* pass the event to the `PolicyEngine` to ensure no security rule is bypassed due to a missing routing key.
