package polynomial

import (
	"fmt"
	"gkr-mimc/common"
	"gkr-mimc/sumcheck"
	"testing"

	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gurvy"
)

type multilinearPolyTestCircuit struct {
	P     MultilinearByValues
	XEval []frontend.Variable
	YEval frontend.Variable
}

func allocateMultilinearTestCircuit(nVars int) multilinearPolyTestCircuit {
	return multilinearPolyTestCircuit{
		P:     AllocateMultilinear(nVars),
		XEval: make([]frontend.Variable, nVars),
	}
}

func (m *multilinearPolyTestCircuit) Define(curveID gurvy.ID, cs *frontend.ConstraintSystem) error {
	actualEval := m.P.Eval(cs, m.XEval)
	cs.AssertIsEqual(actualEval, m.YEval)
	return nil
}

func TestMultilinear(t *testing.T) {
	assert := groth16.NewAssert(t)
	nVars := 4

	m := allocateMultilinearTestCircuit(nVars)

	// Attempt to compile the circuit
	r1cs, err := frontend.Compile(gurvy.BN256, &m)
	assert.NoError(err)

	fmt.Printf("Nb constraints = %v", r1cs.GetNbConstraints())

	// Creates a witness
	witness := allocateMultilinearTestCircuit(nVars)
	values := make([]interface{}, 1<<nVars)
	for i := range values {
		values[i] = i
	}

	p := common.RandomFrArray(1 << nVars)
	x := common.RandomFrArray(nVars)

	bkt := sumcheck.NewBookKeepingTable(p)
	y := bkt.Evaluate(x)

	witness.P.Assign(common.FrToGenericArray(p))

	for i := 0; i < nVars; i++ {
		witness.XEval[i].Assign(x[i])
	}
	witness.YEval.Assign(y)

	assert.SolvingSucceeded(r1cs, &witness)
}
