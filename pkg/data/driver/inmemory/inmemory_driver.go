// SPDX-License-Identifier: AGPL-3.0-or-later
package inmemory

import (
	"context"
	"errors"
	"fmt"
	"sync"
)

// InMemoryDriver is a simple, volatile implementation of the DataDriver interface.
type InMemoryDriver struct {
	mu        sync.RWMutex
	data      map[string][]map[string]interface{}
	connected bool
}

func NewInMemoryDriver() *InMemoryDriver {
	return &InMemoryDriver{
		data: make(map[string][]map[string]interface{}),
	}
}

func (d *InMemoryDriver) Name() string {
	return "inmemory"
}

func (d *InMemoryDriver) Connect(ctx context.Context, connectionString string) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.connected = true
	return nil
}

func (d *InMemoryDriver) Disconnect(ctx context.Context) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.connected = false
	d.data = make(map[string][]map[string]interface{})
	return nil
}

func (d *InMemoryDriver) Execute(ctx context.Context, query string, args ...interface{}) (int64, error) {
	if !d.connected {
		return 0, errors.New("driver not connected")
	}
	
	d.mu.Lock()
	defer d.mu.Unlock()

	// Very naive: Treat query as table name and args[0] as the data row
	if len(args) > 0 {
		if row, ok := args[0].(map[string]interface{}); ok {
			d.data[query] = append(d.data[query], row)
			return 1, nil
		}
	}

	return 0, errors.New("unsupported execute command for in-memory driver")
}

func (d *InMemoryDriver) Query(ctx context.Context, query string, args ...interface{}) (ResultIterator, error) {
	if !d.connected {
		return nil, errors.New("driver not connected")
	}

	d.mu.RLock()
	defer d.mu.RUnlock()

	rows, ok := d.data[query]
	if !ok {
		return nil, fmt.Errorf("table %s not found", query)
	}

	snapshot := make([]map[string]interface{}, len(rows))
	copy(snapshot, rows)

	return &inMemoryIterator{
		data:  snapshot,
		index: -1, // Start at -1 so Next() moves to 0
	}, nil
}

type inMemoryIterator struct {
	data  []map[string]interface{}
	index int
}

func (it *inMemoryIterator) Next() bool {
	it.index++
	return it.index < len(it.data)
}

func (it *inMemoryIterator) Scan(dest ...interface{}) error {
	if len(dest) == 0 {
		return errors.New("no destination provided")
	}
	ptr, ok := dest[0].(*map[string]interface{})
	if !ok {
		return errors.New("destination must be a pointer to map[string]interface{}")
	}

	if it.index < 0 || it.index >= len(it.data) {
		return errors.New("no more rows")
	}

	*ptr = it.data[it.index]
	return nil
}

func (it *inMemoryIterator) Close() error {
	return nil
}

func (it *inMemoryIterator) Err() error {
	return nil
}
