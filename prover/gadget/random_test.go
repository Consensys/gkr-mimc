package gadget

import (
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/frontend"
	"github.com/stretchr/testify/assert"
)

// RandomCircuit tests all possibilities that the circuit can
type RandomCircuit struct {
	Public  []frontend.Variable `gnark:",public"`
	Private []frontend.Variable
}

func AllocateRandomCircuit(n int) RandomCircuit {
	return RandomCircuit{
		Public:  make([]frontend.Variable, n),
		Private: make([]frontend.Variable, n),
	}
}

// In order to simplify the test, we make the calculation feed-forward
func (c *RandomCircuit) Define(curveID ecc.ID, cs frontend.API, gadget *GkrGadget) error {
	tmp := cs.Constant(1)
	for i := range c.Public {
		tmp := gadget.UpdateHasher(cs, tmp, c.Public[i])
		tmp = gadget.UpdateHasher(cs, tmp, tmp)
		tmp = gadget.UpdateHasher(cs, tmp, c.Private[i])
		tmp = cs.Mul(tmp, tmp)

	}
	return nil
}

// Assigns deterministic values
func (c *RandomCircuit) Assign() []fr.Element {
	res := make([]fr.Element, len(c.Public))
	for i := range c.Private {
		res[i].SetRandom()
		c.Public[i].Assign(res[i])
		c.Private[i].Assign(i + 970797)
	}
	return res
}

func TestWithRandomCircuit(t *testing.T) {
	n := 10

	innerCircuit := AllocateRandomCircuit(n)
	circuit := WrapCircuitUsingGkr(&innerCircuit, WithChunkSize(32), WithNCore(1))

	r1cs, err := circuit.Compile()
	assert.NoError(t, err)

	pk, vk, err := Setup(&r1cs)
	assert.NoError(t, err)

	innerAssignment := AllocateRandomCircuit(n)
	pubWitness := innerAssignment.Assign()
	assignment := WrapCircuitUsingGkr(&innerAssignment, WithChunkSize(32), WithNCore(1))
	assignment.Assign()

	// Test correct assignment
	assert.NotNil(t, assignment.Gadget.InitialRandomness.WitnessValue)
	assert.NotNil(t, innerAssignment.Public[0].WitnessValue)
	assert.NotNil(t, innerAssignment.Private[0].WitnessValue)

	solution, err := assignment.Solve(r1cs)
	assert.NoError(t, err)
	initialRandomness := solution.Wires[1]

	proof, err := ComputeProof(&r1cs, &pk, solution, assignment.Gadget.proof)
	assert.NoError(t, err)

	err = Verify(proof, &vk, append([]fr.Element{initialRandomness}, pubWitness...))
	assert.NoError(t, err)

}
