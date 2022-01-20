package gadget

import (
	"testing"

	"github.com/AlexandreBelling/gnark/backend"
	grothBack "github.com/AlexandreBelling/gnark/backend/groth16"
	"github.com/AlexandreBelling/gnark/notinternal/backend/bn254/groth16"
	"github.com/AlexandreBelling/gnark/notinternal/backend/bn254/witness"
	"github.com/consensys/gkr-mimc/hash"
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
	witness := witness.Witness{}
	err = witness.FromFullAssignment(&assignment)
	assert.NoError(t, err)

	// If we are not mistaken, this should be zero at this point
	assert.Equal(t, witness[0], fr.NewElement(0))
	// And then, we complete the solution with the initial randomness
	witness[0] = solution.Wires[1]

	// Reset the index,
	assignment.Gadget.ioStore.index = 0

	opts := backend.WithHints(
		assignment.Gadget.InitialRandomnessHint(),
		assignment.Gadget.HashHint(),
		assignment.Gadget.GkrProverHint(),
	)
	proverOption, err := backend.NewProverOption(opts)
	assert.NoError(t, err)

	_, _, _, _, err = groth16.Solve(&r1cs.r1cs, witness, proverOption)
	assert.NoError(t, err)
}

// Make sure that it works when we use the standard gnark Prover interface
// and the one we use by splitt
func TestGadgetProver(t *testing.T) {
	n := 10
	preimages := make([]fr.Element, n)
	hashes := make([]fr.Element, n)

	for i := range preimages {
		preimages[i].SetUint64(uint64(i))
		hash.MimcUpdateInplace(&hashes[i], preimages[i])
	}

	innerCircuit := AllocateTestGadgetCircuit(n)
	circuit := WrapCircuitUsingGkr(&innerCircuit, WithMinChunkSize(16), WithNCore(1))

	r1cs, err := circuit.Compile()
	assert.NoError(t, err)
	assert.Equal(t, len(r1cs.pubNotGkrVarID), 1) // One for the initial randomness

	_, _, pub := r1cs.r1cs.GetNbVariables()
	assert.Equal(t, pub, 2) // One for the initial randomness + 1 for the constant = 1

	// In order for the solving to work we also need to run the
	// variant..
	_, _, err = DummySetup(&r1cs)
	assert.NoError(t, err)

	// Run the actual Groth16 prover on it
	pk, vk, err := grothBack.Setup(&r1cs.r1cs)
	assert.NoError(t, err)

	innerAssignment := AllocateTestGadgetCircuit(n)
	innerAssignment.Assign(preimages, hashes)
	assignment := WrapCircuitUsingGkr(&innerAssignment, WithMinChunkSize(16), WithNCore(1))
	assignment.Assign()

	// Run the solver
	solution, err := assignment.Solve(r1cs)
	assert.NoError(t, err)

	// Catch the initial randomness into a specific value
	// to avoid having it "destroyed" by the compute proof
	initialRandomnessVal := solution.Wires[1]

	proofComputed, err := groth16.ComputeProof(
		&r1cs.r1cs, pk.(*groth16.ProvingKey),
		solution.A, solution.B, solution.C, solution.Wires,
	)
	assert.NoError(t, err)

	// Call the verifier on it
	publicWitness := []fr.Element{initialRandomnessVal} // only contains the initial randomness
	err = groth16.Verify(proofComputed, vk.(*groth16.VerifyingKey), publicWitness)
	assert.NoError(t, err)
}

// Test for the prover when it is not split
func TestGadgetWithOldProver(t *testing.T) {
	n := 10
	preimages := make([]fr.Element, n)
	hashes := make([]fr.Element, n)

	for i := range preimages {
		preimages[i].SetUint64(uint64(i))
		hash.MimcUpdateInplace(&hashes[i], preimages[i])
	}

	innerCircuit := AllocateTestGadgetCircuit(n)
	circuit := WrapCircuitUsingGkr(&innerCircuit, WithMinChunkSize(16), WithNCore(1))

	r1cs, err := circuit.Compile()
	assert.NoError(t, err)
	assert.Equal(t, len(r1cs.pubNotGkrVarID), 1) // One for the initial randomness

	_, _, pub := r1cs.r1cs.GetNbVariables()
	assert.Equal(t, pub, 2) // One for the initial randomness + 1 for the constant = 1

	// In order for the solving to work we also need to run the
	// variant..
	// This will inject the proving key inside the r1cs
	_, _, err = DummySetup(&r1cs)
	assert.NoError(t, err)

	// Run the actual Groth16 prover on it
	pk, vk, err := grothBack.Setup(&r1cs.r1cs)
	assert.NoError(t, err)

	innerAssignment := AllocateTestGadgetCircuit(n)
	innerAssignment.Assign(preimages, hashes)
	assignment := WrapCircuitUsingGkr(&innerAssignment, WithMinChunkSize(16), WithNCore(1))
	assignment.Assign()

	solution, err := assignment.Solve(r1cs)
	assert.NoError(t, err)

	// Reassign a witness with the right initial randomness
	innerAssignment = AllocateTestGadgetCircuit(n)
	innerAssignment.Assign(preimages, hashes)
	assignment = WrapCircuitUsingGkr(&innerAssignment, WithMinChunkSize(16), WithNCore(1))

	// In order for the solving to pass, we need to inject the r1cs and give the right value
	assignment.Gadget.InitialRandomness = solution.Wires[1]
	assignment.Gadget.r1cs = &r1cs
	opts := backend.WithHints(
		assignment.Gadget.InitialRandomnessHint(),
		assignment.Gadget.HashHint(),
		assignment.Gadget.GkrProverHint(),
	)

	// Normally, the solver should be happy
	err = grothBack.IsSolved(&r1cs.r1cs, &assignment, opts)
	assert.NoError(t, err)

	proof, err := grothBack.Prove(
		&r1cs.r1cs, pk, &assignment,
		opts,
	)
	assert.NoError(t, err)

	// only contains the initial randomness
	publicWitness := Circuit{}
	publicWitness.Gadget.InitialRandomness = solution.Wires[1]
	err = grothBack.Verify(proof, vk, &publicWitness)
	assert.NoError(t, err)

}
