package gkr

import (
	"fmt"
	"testing"

	"github.com/consensys/gkr-mimc/common"
	"github.com/consensys/gkr-mimc/examples"
	"github.com/consensys/gkr-mimc/poly"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/stretchr/testify/assert"
)

func TestGKR(t *testing.T) {

	bn := 2

	var one fr.Element
	one.SetOne()

	c := examples.Mimc()

	block := common.RandomFrArray(1 << bn)
	initstate := common.RandomFrArray(1 << bn)
	qPrime := common.RandomFrArray(bn)

	a := c.Assign(block, initstate)
	// Gets a deep-copy of the assignment
	a2 := c.Assign(block, initstate)

	proof := Prove(c, a, qPrime)

	// Check that the claims are consistents with the assignment
	for layer := len(c) - 1; layer >= 0; layer-- {
		for j, claim := range proof.Claims[layer] {
			claim2 := a2[layer].Evaluate(proof.QPrimes[layer][j])

			if claim2 != claim {
				panic(fmt.Sprintf("inconsistent claim at layer %v no %v, %v != %v", layer, j, claim.String(), claim2.String()))
			}

			assert.Equal(t, claim2.String(), proof.Claims[layer][j].String())
		}
	}

	err := Verify(c, proof, []poly.MultiLin{block, initstate}, a2[93].DeepCopy(), qPrime)
	assert.NoError(t, err)
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

	c := examples.Mimc()

	block := common.RandomFrArray(1 << bn)
	initstate := common.RandomFrArray(1 << bn)
	qPrime := common.RandomFrArray(bn)

	a := c.Assign(block, initstate)

	b.ResetTimer()

	common.ProfileTrace(b, false, true, func() {
		_ = Prove(c, a, qPrime)
	})

}
