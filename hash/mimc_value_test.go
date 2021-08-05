package hash

import (
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

func TestMimcValue(t *testing.T) {

	var state, block fr.Element
	state.SetZero()
	block.SetUint64(123)
	MimcUpdateInplace(&state, block)

	println(state.String())
}
