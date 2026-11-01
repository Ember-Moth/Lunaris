// Derived from XTLS/Xray-core common/crypto at b17a88f9b46d.
// Licensed under MPL-2.0; see LICENSES/MPL-2.0/MPL-2.0.txt.
package encryption

import (
	"crypto/rand"
	"math/big"
)

func randBetween(from, to int64) int64 {
	if from == to {
		return from
	}
	if from > to {
		from, to = to, from
	}
	value, err := rand.Int(rand.Reader, big.NewInt(to-from))
	if err != nil {
		panic(err)
	}
	return from + value.Int64()
}

func maximum(left, right int) int {
	if left > right {
		return left
	}
	return right
}

func maximum64(left, right int64) int64 {
	if left > right {
		return left
	}
	return right
}
