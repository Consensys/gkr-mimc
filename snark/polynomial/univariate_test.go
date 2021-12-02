package polynomial

import (
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
)

type univariateTestCircuit struct {
	Poly     Univariate
	ZnO      frontend.Variable // for testing purposes only
	Expected frontend.Variable // for testing purposes only
}

func (pc *univariateTestCircuit) Define(curveID ecc.ID, cs frontend.API) error {

	zno := pc.Poly.ZeroAndOne(cs)
	x := cs.Constant(5)
	PAtX := pc.Poly.Eval(cs, x)

	cs.AssertIsEqual(zno, pc.ZnO)
	cs.AssertIsEqual(PAtX, pc.Expected)

	return nil
}

func TestUnivariate(t *testing.T) {

	degree := 3
	var pc univariateTestCircuit
	pc.Poly = AllocateUnivariate(degree)
	//r1cs, err := frontend.Compile(ecc.BN254, backend.GROTH16, &pc)
	assert := test.NewAssert(t)
	//assert.NoError(err)

	var witness univariateTestCircuit
	witness.Poly.Coefficients = make([]frontend.Variable, 4)
	// witness <---> X^3 + 2X^2 + 3X + 4
	witness.Poly.Coefficients[0].Assign(4)
	witness.Poly.Coefficients[1].Assign(3)
	witness.Poly.Coefficients[2].Assign(2)
	witness.Poly.Coefficients[3].Assign(1)
	witness.ZnO.Assign(14)
	witness.Expected.Assign(194)

	assert.ProverSucceeded(&pc, &witness, test.WithCurves(ecc.BN254))

}
