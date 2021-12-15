package gadget

import (
	"testing"

	"github.com/consensys/gkr-mimc/hash"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/stretchr/testify/assert"
)

func TestFullProver(t *testing.T) {
	n := 10
	preimages := make([]fr.Element, n)
	hashes := make([]fr.Element, n)

	for i := range preimages {
		preimages[i].SetUint64(uint64(i))
		hash.MimcUpdateInplace(&hashes[i], preimages[i])
	}

	innerCircuit := AllocateTestGadgetCircuit(n)
	circuit := WrapCircuitUsingGkr(&innerCircuit, WithChunkSize(16), WithNCore(1))

	r1cs, err := circuit.Compile()
	assert.NoError(t, err)

	pk, vk, err := Setup(&r1cs)

	innerAssignment := AllocateTestGadgetCircuit(n)
	innerAssignment.Assign(preimages, hashes)
	assignment := WrapCircuitUsingGkr(&innerAssignment, WithChunkSize(16), WithNCore(1))
	assignment.Assign()

	solution, err := assignment.Solve(r1cs)
	assert.NoError(t, err)

	// Catch the initial randomness into a specific value
	// to avoid having it "destroyed" by the compute proof
	initialRandomnessVal := solution.Wires[1]

	proof, err := ComputeProof(
		&r1cs,
		&pk,
		solution,
		assignment.Gadget.proof,
	)
	assert.NoError(t, err)

	err = Verify(proof, &vk, []fr.Element{initialRandomnessVal})
	assert.NoError(t, err)
}
