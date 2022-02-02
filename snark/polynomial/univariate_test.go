package polynomial

import (
	"testing"

	"github.com/AlexandreBelling/gnark/backend"
	"github.com/AlexandreBelling/gnark/frontend"
	"github.com/AlexandreBelling/gnark/test"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/stretchr/testify/assert"
)

type univariateTestCircuit struct {
	Poly     Univariate
	ZnO      frontend.Variable // for testing purposes only
	Expected frontend.Variable // for testing purposes only
}

func (pc *univariateTestCircuit) Define(cs frontend.API) error {

	zno := pc.Poly.ZeroAndOne(cs)
	x := frontend.Variable(5)
	PAtX := pc.Poly.Eval(cs, x)

	cs.AssertIsEqual(zno, pc.ZnO)
	cs.AssertIsEqual(PAtX, pc.Expected)

	return nil
}

func TestUnivariate(t *testing.T) {

	degree := 3
	var pc univariateTestCircuit
	pc.Poly = AllocateUnivariate(degree)
	_, err := frontend.Compile(ecc.BN254, backend.GROTH16, &pc)
	assert.NoError(t, err)

	var witness univariateTestCircuit
	witness.Poly.Coefficients = make([]frontend.Variable, 4)
	// witness <---> X^3 + 2X^2 + 3X + 4
	witness.Poly.Coefficients[0] = 4
	witness.Poly.Coefficients[1] = 3
	witness.Poly.Coefficients[2] = 2
	witness.Poly.Coefficients[3] = 1
	witness.ZnO = 14
	witness.Expected = 194

	assert.NoError(t, test.IsSolved(&pc, &witness, ecc.BN254, backend.GROTH16))

}
