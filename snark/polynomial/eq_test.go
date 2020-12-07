package polynomial

import (
	"gkr-mimc/common"
	"gkr-mimc/gkr"
	"testing"

	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gurvy"
	"github.com/consensys/gurvy/bn256/fr"
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
			eq.H[k][n].Assign(H[k][n])
			eq.Q[k][n].Assign(Q[k][n])
		}
		eq.ExpectedValue[k].Assign(gkr.EvalEq(Q[k], H[k]))
	}
}

func (eq *TestEqCircuit) Define(curveID gurvy.ID, cs *frontend.ConstraintSystem) error {
	for i := range eq.H {
		h := EqEval(cs, eq.H[i], eq.Q[i])
		cs.AssertIsEqual(h, eq.ExpectedValue[i])
	}
	return nil
}

func TestEq(t *testing.T) {

	eq := AllocateTestEqCircuit(5, 5)
	r1cs, err := frontend.Compile(gurvy.BN256, &eq)

	assert := groth16.NewAssert(t)
	assert.NoError(err)

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
	assert.SolvingSucceeded(r1cs, &witness)
	assert.ProverSucceeded(r1cs, &witness)
}
