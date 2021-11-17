package polynomial

import (
	"testing"

	"github.com/consensys/gkr-mimc/common"
	"github.com/consensys/gkr-mimc/polynomial"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
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

func (m *multilinearPolyTestCircuit) Define(cs frontend.API) error {
	actualEval := m.P.Eval(cs, m.XEval)
	cs.AssertIsEqual(actualEval, m.YEval)
	return nil
}

func TestMultilinear(t *testing.T) {
	assert := test.NewAssert(t)
	nVars := 4

	m := allocateMultilinearTestCircuit(nVars)

	// Creates a witness
	witness := allocateMultilinearTestCircuit(nVars)
	values := make([]interface{}, 1<<nVars)
	for i := range values {
		values[i] = i
	}

	p := common.RandomFrArray(1 << nVars)
	x := common.RandomFrArray(nVars)

	bkt := polynomial.NewBookKeepingTable(p)
	y := bkt.Evaluate(x)

	witness.P.Assign(common.FrToGenericArray(p))

	for i := 0; i < nVars; i++ {
		witness.XEval[i] = x[i]
	}
	witness.YEval = y

	assert.SolvingSucceeded(&m, &witness, test.WithBackends(backend.GROTH16), test.WithCurves(ecc.BN254))
}
