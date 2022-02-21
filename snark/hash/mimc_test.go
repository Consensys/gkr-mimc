package hash

import (
	"fmt"
	"testing"

	"github.com/consensys/gkr-mimc/common"
	"github.com/consensys/gkr-mimc/hash"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
)

type TestMimcCircuit struct {
	X [][]frontend.Variable
	Y []frontend.Variable
}

func (c *TestMimcCircuit) Define(cs frontend.API) error {
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
			c.X[k][n] = x[k][n]
		}
		y := hash.MimcHash(x[k])
		c.Y[k] = y
	}
}

func TestMimc(t *testing.T) {

	assert := test.NewAssert(t)
	c := Allocate(5, 5)

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
	assert.SolvingSucceeded(&c, &witness, test.WithBackends(backend.GROTH16), test.WithCurves(ecc.BN254))
}

func BenchmarkMimc(b *testing.B) {

	// This will expand the benchmark until, a SEGFAULT happens
	// Or there is enough memory to run 32M hashes (=> impossible)
	for bn := 10; bn < 25; bn++ {
		fmt.Printf("Baseline Mimc7 benchmark bN = %v\n", bn)

		c := Allocate(1<<bn, 1)
		r1cs, _ := frontend.Compile(ecc.BN254, backend.GROTH16, &c)

		x := make([][]fr.Element, 1<<bn)
		for i := range x {
			x[i] = common.RandomFrArray(1)
		}

		fmt.Printf("Nb constraints = %v\n", r1cs.GetNbConstraints())

		// Generate the witness values by running the prover
		var witness TestMimcCircuit

		b.Run("Gnark circuit assignment", func(b *testing.B) {
			b.StopTimer()
			for i := 0; i < b.N; i++ {
				witness = Allocate(1<<bn, 1)
				b.StartTimer()
				witness.Assign(x)
				b.StopTimer()
			}
		})

		pk, _ := groth16.DummySetup(r1cs)
		b.Run("Gnark prover", func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				w, _ := frontend.NewWitness(&witness, ecc.BN254)
				_, err := groth16.Prove(r1cs, pk, w)
				if err != nil {
					panic(err)
				}
			}
		})
	}

}
