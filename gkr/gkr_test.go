package gkr

import (
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
	proof := Prove(c, a, qPrime)

	err := Verify(c, proof, []poly.MultiLin{block, initstate}, a[93].DeepCopy(), qPrime)
	assert.NoError(t, err)
}
