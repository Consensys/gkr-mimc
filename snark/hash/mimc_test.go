package hash

import (
	"fmt"
	"gkr-mimc/common"
	"gkr-mimc/hash"
	"os"
	"strconv"
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

func BenchmarkMimc(b *testing.B) {

	bN, _ := strconv.Atoi(os.Getenv("BN_GKR"))

	c := Allocate(1<<bN, 1)
	r1cs, _ := frontend.Compile(gurvy.BN256, &c)

	x := make([][]fr.Element, 1<<bN)
	for i := range x {
		x[i] = common.RandomFrArray(1)
	}

	fmt.Printf("Nb constraints = %v\n", r1cs.GetNbConstraints())

	// Generate the witness values by running the prover
	var witness TestMimcCircuit

	b.Run("Gnark circuit assignment", func(b *testing.B) {
		b.StopTimer()
		for i := 0; i < b.N; i++ {
			witness = Allocate(1<<bN, 1)
			b.StartTimer()
			witness.Assign(x)
			b.StopTimer()
		}
	})

	pk := groth16.DummySetup(r1cs)
	b.Run("Gnark prover", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, _ = groth16.Prove(r1cs, pk, &witness)
		}
	})

}
