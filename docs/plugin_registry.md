# Plugin Registry Documentation

The `Registry` is the central management authority for all loaded plugins within Project Titan's Kernel. It ensures that plugin lifecycles (Registration $\rightarrow$ Lookup $\rightarrow$ Unregistration) are managed in a thread-safe manner, preventing conflicts and providing visibility into active capabilities.

## Core Responsibilities
- **Plugin Onboarding**: Validates and stores new `Plugin` instances.
- **Conflict Prevention**: Enforces unique plugin names to prevent accidental overwrites or "name squatting."
- **Capability Discovery**: Provides an efficient $O(1)$ lookup mechanism for the Kernel to retrieve specific plugins by name.
- **Lifecycle Auditing**: Maintains a list of all active plugins for monitoring and system status reporting.

## Implementation Details
The registry is implemented using `sync.Map`, making it safe for concurrent use across multiple goroutines (e.g., during high-frequency request processing or dynamic plugin hot-reloading).

### Key Methods

#### `Register(p Plugin) error`
Adds a plugin to the registry. 
- **Constraint**: If a plugin with the same name is already registered, it returns an error.
- **Safety**: Checks for `nil` plugin inputs.

#### `Get(name string) (Plugin, error)`
Retrieves a specific plugin by its unique identifier.
- **Returns**: The `Plugin` instance if found; otherwise, returns an error indicating the plugin was not found.

#### `Remove(name string) error`
Unregisters and removes a plugin from the active list.
- **Returns**: An error if the attempt fails because the plugin does not exist.

#### `List() []string`
Scans the registry and returns a slice of all currently registered plugin names. Useful for system health checks and dashboarding.

## Usage Example

```go
// Initialize the registry
registry := plugin.NewRegistry()

// Register a new capability
err := registry.Register(myNewPlugin)
if err != nil {
    log.Fatalf("Failed to register plugin: %v", err)
}

// Retrieve and use a plugin
p, err := registry.Get("auth-plugin")
if err == nil {
    p.HandleRequest(ctx, req)
}
```
