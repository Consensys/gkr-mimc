package gadget

import (
	"testing"

	"github.com/consensys/gkr-mimc/hash"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/backend"
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

func TestGadgetProof(t *testing.T) {
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

	// We need to at least run the dummy setup so that the solver knows what to do
	// So that the proving key can attach itself to the R1CS
	pk, vk, err := Setup(&r1cs)
	assert.NoError(t, err)

	innerAssignment := AllocateTestGadgetCircuit(n)
	innerAssignment.Assign(preimages, hashes)
	assignment := WrapCircuitUsingGkr(&innerAssignment, WithChunkSize(16), WithNCore(1))
	assignment.Assign()

	solution, err := assignment.Solve(r1cs)
	assert.NoError(t, err)

	proof, err := ComputeProof(&r1cs, &pk, solution, &assignment.Gadget.proof)
	assert.NoError(t, err)

	publicWitness := make([]fr.Element, 1)
	err = Verify(proof, &vk, publicWitness)
	assert.NoError(t, err)

}
