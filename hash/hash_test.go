package hash

import (
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/stretchr/testify/assert"
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

func TestMimcCase(t *testing.T) {
	var x, expectedY fr.Element
	x.SetString("12")
	y := MimcHash([]fr.Element{x})
	expectedY.SetString("1808205620575546259657963589762746470347087906694759866517376279978241663265")
	assert.Equal(t, y, expectedY, "Got %v", y.String())
}
