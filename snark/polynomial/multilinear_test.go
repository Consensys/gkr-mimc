package polynomial

import (
	"fmt"
	"testing"

	"github.com/consensys/gkr-mimc/common"
	"github.com/consensys/gkr-mimc/polynomial"
	"github.com/stretchr/testify/assert"

	"github.com/AlexandreBelling/gnark/backend"
	"github.com/AlexandreBelling/gnark/backend/groth16"
	"github.com/AlexandreBelling/gnark/frontend"
	"github.com/consensys/gnark-crypto/ecc"
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

func (m *multilinearPolyTestCircuit) Define(curveID ecc.ID, cs frontend.API) error {
	actualEval := m.P.Eval(cs, m.XEval)
	cs.AssertIsEqual(actualEval, m.YEval)
	return nil
}

func TestMultilinear(t *testing.T) {
	nVars := 4

	m := allocateMultilinearTestCircuit(nVars)

	// Attempt to compile the circuit
	r1cs, err := frontend.Compile(ecc.BN254, backend.GROTH16, &m)
	assert.NoError(t, err)

	fmt.Printf("Nb constraints = %v", r1cs.GetNbConstraints())

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
		witness.XEval[i].Assign(x[i])
	}
	witness.YEval.Assign(y)

	assert.NoError(t, groth16.IsSolved(r1cs, &witness))
}
