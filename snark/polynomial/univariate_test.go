package polynomial

import (
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
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
	witness.Poly[0] = frontend.Variable(4)
	witness.Poly[1] = frontend.Variable(3)
	witness.Poly[2] = frontend.Variable(2)
	witness.Poly[3] = frontend.Variable(1)
	witness.ZnO = frontend.Variable(14)
	witness.Expected = frontend.Variable(194)
	t.Log(3)

	assert.ProverSucceeded(&pc, &witness, test.WithBackends(backend.GROTH16), test.WithCurves(ecc.BN254))
}
