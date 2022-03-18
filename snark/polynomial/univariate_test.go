package polynomial

import (
	"testing"

	"github.com/AlexandreBelling/gnark/backend"
	"github.com/AlexandreBelling/gnark/frontend"
	"github.com/AlexandreBelling/gnark/test"
	"github.com/consensys/gnark-crypto/ecc"
)

type univariateTestCircuit struct {
	Poly     Univariate
	ZnO      frontend.Variable // for testing purposes only
	Expected frontend.Variable // for testing purposes only
}

func (pc *univariateTestCircuit) Define(cs frontend.API) error {

	zno := pc.Poly.ZeroAndOne(cs)
	x := 5
	PAtX := pc.Poly.Eval(cs, x)

	cs.AssertIsEqual(zno, pc.ZnO)
	cs.AssertIsEqual(PAtX, pc.Expected)

	return nil
}

func TestUnivariate(t *testing.T) {

	degree := 3
	var pc univariateTestCircuit
	pc.Poly = AllocateUnivariate(degree)
	assert := test.NewAssert(t)

	var witness univariateTestCircuit
	witness.Poly = make([]frontend.Variable, 4)
	// witness <---> X^3 + 2X^2 + 3X + 4
	witness.Poly[0] = 4
	witness.Poly[1] = 3
	witness.Poly[2] = 2
	witness.Poly[3] = 1
	witness.ZnO = 14
	witness.Expected = 194

	assert.ProverSucceeded(&pc, &witness, test.WithBackends(backend.GROTH16), test.WithCurves(ecc.BN254))

}
