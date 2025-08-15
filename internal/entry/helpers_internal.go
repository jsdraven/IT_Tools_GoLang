// Package entry: Helpers GO
package entry

import (
	"crypto/sha256"
	"encoding/hex"
	"math/big"
)

func sha256SumHex(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:16]) // 128-bit prefix
}

// bigInt1 returns a constant serial number for simplicity.
func bigInt1() *big.Int { return big.NewInt(1) }
