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
	// From finState decrease bu `block` to cancel the last key-addition done in `MimcPermutationUpdate`
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

// func benchmarkMIMCCircuit(b *testing.B, bN, nCore, nChunks int, profiled, traced bool) {
// 	b.ResetTimer()
// 	for i := 0; i < b.N; i++ {
// 		b.StopTimer()
// 		// Initialize the circuit
// 		mimcCircuit := CreateMimcCircuit()
// 		// Performs the assignment
// 		inputs := randomInputs(bN)
// 		assignment := mimcCircuit.Assign(inputs, 1)
// 		// Finally checks the entire GKR protocol
// 		prover := gkr.NewProver(mimcCircuit, assignment)

// 		common.ProfileTrace(b, profiled, traced, func() {
// 			_mimcProof = prover.Prove(nCore)
// 		})
// 	}
// }

// func BenchmarkMimcGKRProver(b *testing.B) {
// 	nChunks := common.GetNChunks()
// 	bN := common.GetBN()
// 	nCore := runtime.GOMAXPROCS(0)
// 	profiled := common.GetProfiled()
// 	traced := common.GetTraced()
// 	b.Run(fmt.Sprintf("bN=%d-nCore", bN), func(b *testing.B) {
// 		benchmarkMIMCCircuit(b, bN, nCore, nChunks, profiled, traced)
// 	})
// }
