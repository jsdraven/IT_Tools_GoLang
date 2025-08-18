package tlsutil

import (
	"crypto/x509"
	"math/big"
	"testing"
	"time"
)

func TestBigInt1(t *testing.T) {
	got := bigInt1()
	if got.Cmp(big.NewInt(1)) != 0 {
		t.Fatalf("bigInt1() = %v, want 1", got)
	}
}

func TestGenerateSelfSigned_WhiteBox(t *testing.T) {
	c, err := GenerateSelfSigned()
	if err != nil {
		t.Fatalf("GenerateSelfSigned: %v", err)
	}
	if c.Leaf == nil {
		t.Fatal("Leaf not set")
	}
	want := bigInt1()
	if c.Leaf.SerialNumber.Cmp(want) != 0 {
		t.Fatalf("serial = %v, want %v", c.Leaf.SerialNumber, want)
	}
	validity := c.Leaf.NotAfter.Sub(c.Leaf.NotBefore)
	if validity < 89*24*time.Hour || validity > 91*24*time.Hour {
		t.Fatalf("validity = %v, want ~90 days", validity)
	}
	if c.Leaf.SignatureAlgorithm != x509.SHA256WithRSA {
		t.Fatalf("SignatureAlgorithm = %v, want %v", c.Leaf.SignatureAlgorithm, x509.SHA256WithRSA)
	}
}
