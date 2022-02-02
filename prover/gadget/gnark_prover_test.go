package gadget

import (
	"testing"

	"github.com/AlexandreBelling/gnark/backend"
	"github.com/AlexandreBelling/gnark/frontend"
	"github.com/AlexandreBelling/gnark/notinternal/backend/bn254/groth16"
	witness_bn254 "github.com/AlexandreBelling/gnark/notinternal/backend/bn254/witness"
	"github.com/consensys/gkr-mimc/hash"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/stretchr/testify/assert"
)

func TestGadgetSolver(t *testing.T) {
	n := 10
	chunkSize := 8
	preimages := make([]fr.Element, n)
	hashes := make([]fr.Element, n)

	for i := range preimages {
		preimages[i].SetUint64(uint64(i))
		hash.MimcUpdateInplace(&hashes[i], preimages[i])
	}

	innerCircuit := AllocateTestGadgetCircuit(n)
	circuit := WrapCircuitUsingGkr(&innerCircuit, WithMinChunkSize(chunkSize), WithNCore(1))

	r1cs, err := circuit.Compile()
	assert.NoError(t, err)

	// Test that the length of the arrays is consistent with what we expect
	_, _, pub := r1cs.r1cs.GetNbVariables()
	assert.Equal(t, pub, 2) // One for the initial randomness + 1 for the constant = 1
	assert.Equal(t, 0, len(r1cs.pubGkrVarID), "Got %v", r1cs.pubGkrVarID)
	assert.Equal(t, []int{1}, r1cs.pubNotGkrVarID, "Got %v", r1cs.pubNotGkrVarID)
	assert.Equal(t, 2*n, len(r1cs.privGkrVarID), "Got %v", r1cs.privGkrVarID)

	// Test that no variable is contained twice and that all variables are contained exactly once
	sumVarIds := 0
	for _, id := range r1cs.privGkrVarID {
		sumVarIds += id
	}

	for _, id := range r1cs.privNotGkrVarID {
		sumVarIds += id
	}

	for _, id := range r1cs.pubGkrVarID {
		sumVarIds += id
	}

	for _, id := range r1cs.pubNotGkrVarID {
		sumVarIds += id
	}

	max := r1cs.privNotGkrVarID[len(r1cs.privNotGkrVarID)-1]
	assert.Equal(t, (max*(max+1))/2, sumVarIds, "The sum should have matched")

	// We need to at least run the dummy setup so that the solver knows what to do
	// So that the proving key can attach itself to the R1CS
	_, _, err = DummySetup(&r1cs)
	assert.NoError(t, err)

	innerAssignment := AllocateTestGadgetCircuit(n)
	innerAssignment.Assign(preimages, hashes)
	assignment := WrapCircuitUsingGkr(&innerAssignment, WithMinChunkSize(chunkSize), WithNCore(1))
	assignment.Assign()

	solution, err := assignment.Solve(r1cs)
	assert.NoError(t, err)
	assert.Equal(t, solution.Wires[0], fr.NewElement(1), "It should be the constant wire")

	// If everything works as intender, it should be possible
	// to completely solve the circuit at once by
	witness, err := frontend.NewWitness(&assignment, ecc.BN254)
	assert.NoError(t, err)
	_w := *witness.Vector.(*witness_bn254.Witness)

	// If we are not mistaken, this should be zero at this point
	assert.Equal(t, _w[0], fr.NewElement(0))
	// And then, we complete the solution with the initial randomness
	_w[0] = solution.Wires[1]

	// Reset the index,
	assignment.Gadget.ioStore.index = 0

	opts := backend.WithHints(
		assignment.Gadget.InitialRandomnessHint(),
		assignment.Gadget.HashHint(),
		assignment.Gadget.GkrProverHint(),
	)
	proverOption, err := backend.NewProverConfig(opts)
	assert.NoError(t, err)

	_, _, _, _, err = groth16.Solve(&r1cs.r1cs, _w, proverOption)
	assert.NoError(t, err)
}
