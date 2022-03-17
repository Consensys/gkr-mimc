package examples

import (
	"testing"

	"github.com/consensys/gkr-mimc/common"
	"github.com/consensys/gkr-mimc/hash"
	"github.com/stretchr/testify/assert"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

func randomInputs(bN int) (keys, state []fr.Element) {
	size := (1 << bN)

	return common.RandomFrArray(size), common.RandomFrArray(size)
}

func TestMimc(t *testing.T) {

	// Initialize the circuit
	mimcCircuit := MimcCircuit()

	assert.True(t, mimcCircuit.IsInputLayer(0))
	assert.True(t, mimcCircuit.IsInputLayer(1))
	assert.Equal(t, mimcCircuit.InputArity(), 2)

	// Test the consistency between the the combinator and the transition function
	bN := 3

	// Performs the assignment
	key, payload := randomInputs(bN)
	a := mimcCircuit.Assign(key, payload)

	outputs := a[93]

	// Sees if the output is consistent with the result of calling Mimc permutation
	finstate0 := hash.MimcKeyedPermutation(payload[0], key[0])

	// An error here indicates a mismatch between the circuit and the mimc permutation
	assert.Equal(t, finstate0.String(), outputs[0].String(), "Error on the state calculation")
}

func TestCircuitForm(t *testing.T) {

	// Initialize the circuit
	circ := MimcCircuit()

	// Test that the Out are always in increasing order
	for l := range circ {
		assert.IsIncreasing(t, circ[l].Out)
	}

}
