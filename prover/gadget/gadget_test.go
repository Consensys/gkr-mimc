package gadget

import (
	"testing"

	"github.com/consensys/gkr-mimc/hash"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/backend"
	grothBack "github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/notinternal/backend/bn254/groth16"
	"github.com/consensys/gnark/notinternal/backend/bn254/witness"
	"github.com/stretchr/testify/assert"
)

// Small circuit to perform a few hashes
type TestGadgetCircuit struct {
	Preimages []frontend.Variable
	Hashes    []frontend.Variable
}

// Allocate the test gadget
func AllocateTestGadgetCircuit(n int) TestGadgetCircuit {
	return TestGadgetCircuit{
		Preimages: make([]frontend.Variable, n),
		Hashes:    make([]frontend.Variable, n),
	}
}

func (t *TestGadgetCircuit) Define(curveID ecc.ID, cs frontend.API, gadget *GkrGadget) error {
	for i := range t.Preimages {
		y := gadget.UpdateHasher(cs, cs.Constant(0), t.Preimages[i])
		cs.AssertIsEqual(t.Hashes[i], y)
	}

	return nil
}

func (t *TestGadgetCircuit) Assign(preimages, hashes []fr.Element) {
	for i := range preimages {
		t.Preimages[i].Assign(preimages[i])
		t.Hashes[i].Assign(hashes[i])
	}
}

func TestGadgetSolver(t *testing.T) {
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
	assignment := WrapCircuitUsingGkr(&innerAssignment, WithChunkSize(16), WithNCore(1))
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

	opts := backend.WithHints(
		assignment.Gadget.InitialRandomnessHint,
		assignment.Gadget.HashHint,
		assignment.Gadget.GkrProverHint,
	)
	proverOption, err := backend.NewProverOption(opts)

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
	circuit := WrapCircuitUsingGkr(&innerCircuit, WithChunkSize(16), WithNCore(1))

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
	assignment := WrapCircuitUsingGkr(&innerAssignment, WithChunkSize(16), WithNCore(1))
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

	publicWitness := []fr.Element{initialRandomnessVal} // only contains the initial randomness
	err = groth16.Verify(proofComputed, vk.(*groth16.VerifyingKey), publicWitness)
	assert.NoError(t, err)

	// Call the "traditional prover"

	// Reassign a witness with the right initial randomness
	innerAssignment = AllocateTestGadgetCircuit(n)
	innerAssignment.Assign(preimages, hashes)
	assignment = WrapCircuitUsingGkr(&innerAssignment, WithChunkSize(16), WithNCore(1))

	// In order for the solving to pass, we need to inject the r1cs and give the right value
	assignment.Gadget.InitialRandomness.Assign(initialRandomnessVal)
	assignment.Gadget.r1cs = &r1cs
	opts := backend.WithHints(
		assignment.Gadget.InitialRandomnessHint,
		assignment.Gadget.HashHint,
		assignment.Gadget.GkrProverHint,
	)

	// Normally, the solver should be happy
	err = grothBack.IsSolved(&r1cs.r1cs, &assignment, opts)
	assert.NoError(t, err)

	proofOld, err := grothBack.Prove(
		&r1cs.r1cs, pk, &assignment,
		opts,
	)
	assert.NoError(t, err)

	// Verifies that proof old works
	publicWitnessOld := Circuit{}
	publicWitnessOld.Gadget.InitialRandomness.Assign(initialRandomnessVal)
	err = grothBack.Verify(proofOld, vk, &publicWitnessOld)
	assert.NoError(t, err)

	// Check that we get the same proofs in both cases
	// Can only work if we make the prover deterministic
	// assert.Equal(t, proofOld, proofComputed)
}

// Test for the prover when it is not split
func TestGadgetOldProver(t *testing.T) {
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
	assignment := WrapCircuitUsingGkr(&innerAssignment, WithChunkSize(16), WithNCore(1))
	assignment.Assign()

	solution, err := assignment.Solve(r1cs)
	assert.NoError(t, err)

	// Reassign a witness with the right initial randomness
	innerAssignment = AllocateTestGadgetCircuit(n)
	innerAssignment.Assign(preimages, hashes)
	assignment = WrapCircuitUsingGkr(&innerAssignment, WithChunkSize(16), WithNCore(1))

	// In order for the solving to pass, we need to inject the r1cs and give the right value
	assignment.Gadget.InitialRandomness.Assign(solution.Wires[1])
	assignment.Gadget.r1cs = &r1cs
	opts := backend.WithHints(
		assignment.Gadget.InitialRandomnessHint,
		assignment.Gadget.HashHint,
		assignment.Gadget.GkrProverHint,
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
	publicWitness.Gadget.InitialRandomness.Assign(solution.Wires[1])
	err = grothBack.Verify(proof, vk, &publicWitness)
	assert.NoError(t, err)

}
