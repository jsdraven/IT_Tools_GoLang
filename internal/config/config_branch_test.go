// internal/config/config_branch_test.go
package config

import "testing"

func TestGetenvBoolDefault(t *testing.T) {
	t.Setenv("XBOOL", "YES")
	if !getenvBoolDefault("XBOOL", false) {
		t.Fatal("YES => true")
	}
	t.Setenv("XBOOL", "off")
	if getenvBoolDefault("XBOOL", true) {
		t.Fatal("off => false")
	}
}

func TestGetenvIntDefault(t *testing.T) {
	t.Setenv("XINT", "42")
	if getenvIntDefault("XINT", 0) != 42 {
		t.Fatal("want 42")
	}
	t.Setenv("XINT", "notnum")
	if getenvIntDefault("XINT", 7) != 7 {
		t.Fatal("bad int => default")
	}
}

func TestSplitCSV(t *testing.T) {
	out := splitCSV(" a, ,b , c ")
	if len(out) != 3 || out[0] != "a" || out[1] != "b" || out[2] != "c" {
		t.Fatalf("bad split: %#v", out)
	}
}
