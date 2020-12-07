package polynomial

import (
	"testing"

	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gurvy"
)

type multilinearPolyTestCircuit struct {
	P     MultilinearByValues
	XFold frontend.Variable
	YFold frontend.Variable
	XEval []frontend.Variable
	YEval frontend.Variable
}

func allocateMultilinearTestCircuit(nVars int) multilinearPolyTestCircuit {
	return multilinearPolyTestCircuit{
		P:     AllocateMultilinear(nVars),
		XEval: make([]frontend.Variable, nVars-1),
	}
}

func (m *multilinearPolyTestCircuit) Define(curveID gurvy.ID, cs *frontend.ConstraintSystem) error {
	m.P.Fold(cs, m.XFold)
	cs.AssertIsEqual(m.P.Table[0], m.YFold)
	actualEval := m.P.Eval(cs, m.XEval)
	cs.AssertIsEqual(actualEval, m.YEval)

	return nil
}

func TestMultilinear(t *testing.T) {
	assert := groth16.NewAssert(t)
	nVars := 4

	xFold := 5
	yFold := xFold * (1 << (nVars - 1))

	yEval := yFold
	for i := 0; i < nVars-1; i++ {
		yEval += (nVars - 1 - i) * (1 << i)
	}

	m := allocateMultilinearTestCircuit(nVars)

	// Attempt to compile the circuit
	r1cs, err := frontend.Compile(gurvy.BN256, &m)
	assert.NoError(err)

	// Creates a witness
	witness := allocateMultilinearTestCircuit(nVars)
	values := make([]interface{}, 1<<nVars)
	for i := range values {
		values[i] = i
	}
	witness.P.Assign(values)
	witness.XFold.Assign(xFold)
	witness.YFold.Assign(yFold)

	for i := 0; i < nVars-1; i++ {
		witness.XEval[i].Assign(i + 1)
	}
	witness.YEval.Assign(yEval)

	assert.SolvingSucceeded(r1cs, &witness)
}
