package gkr

import (
	"fmt"
	"testing"

	"github.com/consensys/gkr-mimc/common"
	"github.com/consensys/gkr-mimc/examples"
	"github.com/consensys/gkr-mimc/poly"
	"github.com/consensys/gkr-mimc/sumcheck"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

func TestGKR(t *testing.T) {

	for bn := 0; bn < 12; bn++ {

		var one fr.Element
		one.SetOne()

		c := examples.MimcCircuit()

		block := common.RandomFrArray(1 << bn)
		initstate := common.RandomFrArray(1 << bn)
		qPrime := common.RandomFrArray(bn)

		a := c.Assign(block, initstate)
		// Gets a deep-copy of the assignment
		a2 := c.Assign(block, initstate)
		_ = a2[0].String()

		proof := Prove(c, a, qPrime)

		// Check that the claims are consistents with the assignment
		for layer := len(c) - 1; layer >= 0; layer-- {

			for j, claim := range proof.Claims[layer] {
				claim2 := a2[layer].Evaluate(proof.QPrimes[layer][j])

				if claim2 != claim {
					panic(fmt.Sprintf("at bn = %v, claim inconsistent with assignment at layer %v no %v, %v != %v", bn, layer, j, claim.String(), claim2.String()))
				}
			}
		}

		// Check that the claims are consistents with the layers evaluations
		for layer := len(c) - 1; layer >= 0; layer-- {
			// Skip if this is an input layer
			if c[layer].Gate == nil {
				break
			}

			Xs := a2.InputsOfLayer(c, layer)

			for j, claim := range proof.Claims[layer] {
				qPrime := proof.QPrimes[layer][j]
				claim2 := sumcheck.Evaluation(c[layer].Gate, [][]fr.Element{qPrime}, []fr.Element{}, Xs...)

				if claim2 != claim {
					panic(fmt.Sprintf("inconsistent claim at layer %v no %v, %v != %v", layer, j, claim.String(), claim2.String()))
				}
			}

			for _, X := range Xs {
				poly.DumpLarge(X)
			}

		}

		err := Verify(c, proof, []poly.MultiLin{block, initstate}, a[93], qPrime)
		if err != nil {
			panic(fmt.Sprintf("bn = %v error at gkr verifier : %v", bn, err))
		}

		poly.DumpLarge(a[93])
		poly.DumpLarge(a2...)
	}
}

func BenchmarkGkr(b *testing.B) {
	for bn := 17; bn < 24; bn++ {
		b.Run(fmt.Sprintf("bn-%v", bn), func(b *testing.B) {
			benchmarkGkr(b, bn)
		})
	}
}

func benchmarkGkr(b *testing.B, bn int) {

	var one fr.Element
	one.SetOne()

	c := examples.MimcCircuit()

	block := common.RandomFrArray(1 << bn)
	initstate := common.RandomFrArray(1 << bn)
	qPrime := common.RandomFrArray(bn)

	a := c.Assign(block, initstate)

	b.ResetTimer()

	common.ProfileTrace(b, false, true, func() {
		_ = Prove(c, a, qPrime)
	})

}
