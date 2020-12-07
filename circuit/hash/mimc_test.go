package hash

import (
	"gkr-mimc/common"
	"gkr-mimc/hash"
	"testing"

	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gurvy"
	"github.com/consensys/gurvy/bn256/fr"
)

type TestMimcCircuit struct {
	X [][]frontend.Variable
	Y []frontend.Variable
}

func (c *TestMimcCircuit) Define(curveID gurvy.ID, cs *frontend.ConstraintSystem) error {
	for k := range c.X {
		y := MimcHash(cs, c.X[k]...)
		cs.AssertIsEqual(c.Y[k], y)
	}
	return nil
}

func Allocate(nTests, testSize int) TestMimcCircuit {
	X := make([][]frontend.Variable, nTests)
	Y := make([]frontend.Variable, nTests)
	for k := range X {
		X[k] = make([]frontend.Variable, testSize)
	}

	return TestMimcCircuit{
		X: X,
		Y: Y,
	}
}

func (c *TestMimcCircuit) Assign(x [][]fr.Element) {
	for k := range x {
		for n := range x[k] {
			c.X[k][n].Assign(x[k][n])
		}
		y := hash.MimcHash(x[k])
		c.Y[k].Assign(y)
	}
}

func TestMimc(t *testing.T) {

	assert := groth16.NewAssert(t)
	c := Allocate(5, 5)
	r1cs, err := frontend.Compile(gurvy.BN256, &c)
	assert.NoError(err)

	// Creates a random test vector
	x := [][]fr.Element{
		common.RandomFrArray(5),
		common.RandomFrArray(5),
		common.RandomFrArray(5),
		common.RandomFrArray(5),
		common.RandomFrArray(5),
	}

	witness := Allocate(5, 5)
	witness.Assign(x)
	assert.SolvingSucceeded(r1cs, &witness)
}
