// SPDX-License-Identifier: AGPL-3.0-or-later
package driver

import (
	"context"
)

// DataDriver defines the contract that any database provider plugin must implement.
// This allows the Kernel to interact with any database (Postgres, MySQL, etc.) 
// without knowing its underlying implementation details.
type DataDriver interface {
	// Name returns the unique identifier for this driver (e.							e., "postgres", "mysql").
	Name() string

	// Connect establishes a connection to the data source using the provided connection string.
	Connect(ctx context.Context, connectionString string) error

	// Disconnect safely closes the connection to the data source.
	Disconnect(ctx context.Context) error

	// Execute runs a command that does not return rows (e.g., INSERT, UPDATE, DELETE).
	Execute(ctx context.Context, query string, args ...interface{}) (int64, error)

	// Query executes a query and returns a generic way to iterate over the results.
	// In a real implementation, this would return an abstraction like Rows or a slice of maps.
	Query(ctx context.Context, query string, args ...interface{}) (ResultIterator, error)
}

// ResultIterator provides an abstraction for iterating through rows returned by a query,
// shielding the application layer from database-specific row implementations.
type ResultIterator interface {
	Next() bool
	Scan(dest ...interface{}) error
	Close() error
	Err() error
}
