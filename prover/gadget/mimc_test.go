package gadget

import (
	"testing"

	"github.com/consensys/gkr-mimc/hash"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
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

func TestGadget(t *testing.T) {
	n := 10
	preimages := make([]fr.Element, n)
	hashes := make([]fr.Element, n)

	for i := range preimages {
		preimages[i].SetRandom()
		hash.MimcUpdateInplace(&hashes[i], preimages[i])
	}

	innerCircuit := AllocateTestGadgetCircuit(n)
	circuit := WrapCircuitUsingGkr(&innerCircuit, WithChunkSize(16), WithNCore(1))

	r1cs, err := frontend.Compile(ecc.BN254, backend.GROTH16, &circuit)
	assert.NoError(t, err)

	innerAssignment := AllocateTestGadgetCircuit(n)
	innerAssignment.Assign(preimages, hashes)
	assignment := WrapCircuitUsingGkr(&innerAssignment, WithChunkSize(16), WithNCore(1))
	assignment.Assign()

	proverOpts := func(opt *backend.ProverOption) error {
		opt.HintFunctions = append(
			opt.HintFunctions,
			assignment.Gadget.InitialRandomnessHint,
			assignment.Gadget.HashHint,
			assignment.Gadget.GkrProverHint,
		)
		return nil
	}

	pk, _ := groth16.DummySetup(r1cs)
	_, err = groth16.Prove(r1cs, pk, &assignment, proverOpts)

	assert.NoError(t, err)

}
