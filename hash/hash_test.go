package hash

import (
	"testing"

	"github.com/consensys/gurvy/bn256/fr"
)

func TestHashes(t *testing.T) {
	inputs := make([]fr.Element, 100)
	PoseidonT2.Hash(inputs)
	PoseidonT4.Hash(inputs)
	PoseidonT8.Hash(inputs)
	GMimcT2.Hash(inputs)
	GMimcT4.Hash(inputs)
	GMimcT8.Hash(inputs)
	MimcHash(inputs)
}
