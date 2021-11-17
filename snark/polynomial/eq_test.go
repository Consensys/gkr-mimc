package polynomial

import (
	"testing"

	"github.com/consensys/gkr-mimc/common"
	"github.com/consensys/gkr-mimc/polynomial"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
)

type TestEqCircuit struct {
	H, Q          [][]frontend.Variable
	ExpectedValue []frontend.Variable
}

func AllocateTestEqCircuit(nTests, testSize int) TestEqCircuit {
	H := make([][]frontend.Variable, nTests)
	Q := make([][]frontend.Variable, nTests)
	ExpectedValue := make([]frontend.Variable, nTests)

	for k := range H {
		H[k] = make([]frontend.Variable, testSize)
		Q[k] = make([]frontend.Variable, testSize)
	}

	return TestEqCircuit{
		H:             H,
		Q:             Q,
		ExpectedValue: ExpectedValue,
	}
}

func (eq *TestEqCircuit) Assign(H, Q [][]fr.Element) {
	for k := range H {
		for n := range Q {
			eq.H[k][n] = H[k][n]
			eq.Q[k][n] = Q[k][n]
		}
		eq.ExpectedValue[k] = polynomial.EvalEq(Q[k], H[k])
	}
}

func (eq *TestEqCircuit) Define(cs frontend.API) error {
	for i := range eq.H {
		h := EqEval(cs, eq.H[i], eq.Q[i])
		cs.AssertIsEqual(h, eq.ExpectedValue[i])
	}
	return nil
}

func TestEq(t *testing.T) {

	eq := AllocateTestEqCircuit(5, 5)

	assert := test.NewAssert(t)

	witness := AllocateTestEqCircuit(5, 5)

	H := [][]fr.Element{
		common.RandomFrArray(5),
		common.RandomFrArray(5),
		common.RandomFrArray(5),
		common.RandomFrArray(5),
		common.RandomFrArray(5),
	}

	Q := [][]fr.Element{
		common.RandomFrArray(5),
		common.RandomFrArray(5),
		common.RandomFrArray(5),
		common.RandomFrArray(5),
		common.RandomFrArray(5),
	}

	witness.Assign(H, Q)
	assert.SolvingSucceeded(&eq, &witness, test.WithBackends(backend.GROTH16), test.WithCurves(ecc.BN254))
	assert.ProverSucceeded(&eq, &witness, test.WithBackends(backend.GROTH16), test.WithCurves(ecc.BN254))
}
