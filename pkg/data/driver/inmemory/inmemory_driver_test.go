package inmemory_test

import (
	"context"
	"testing"
	"IT_Tools_GoLang_New/pkg/data/driver/inmemory"
)

func TestInMemoryDriver(t *testing.T) {
	ctx := context.Background()
	drv := inmemory.NewInMemoryDriver()

	// 1. Test Connect
	err := drv.Connect(ctx, "")
	if err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}

	// 2. Test Execute (Insert)
	table := "users"
	row := map[string]interface{}{"id": 1, "name": "Alice"}
	rowsAffected, err := drv.Execute(ctx, table, row)
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}
	if rowsAffected != 1 {
		t.Errorf("Expected 1 row affected, got %d", rowsAffected)
	}

	// 3. Test Query
	iter, err := drv.Query(ctx, table)
	if err != nil {
		t.Fatalf("Query failed: %v", err)
	}
	defer iter.Close()

	if !iter.Next() {
		t.Fatal("Expected at least one row")
	}

	var result map[string]interface{}
	err = iter.Scan(&result)
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}

	if result["name"] != "Alice" {
		t.Errorf("Expected name Alice, got %v", result["name"])
	}

	// 4. Test Disconnect
	err = drv.Disconnect(ctx)
	if err != nil {
		t.Fatalf("Disconnect failed: %v", err)
	}
}
