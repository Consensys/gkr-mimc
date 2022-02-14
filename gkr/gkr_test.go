package gkr

import (
	"testing"

	"github.com/consensys/gkr-mimc/circuit"
	"github.com/consensys/gkr-mimc/common"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

func TestGKR(t *testing.T) {

	bn := 2

	var one fr.Element
	one.SetOne()

	c := circuit.Mimc()

	block := common.RandomFrArray(1 << bn)
	initstate := common.RandomFrArray(1 << bn)
	qPrime := common.RandomFrArray(bn)

	a := c.Assign(block, initstate)
	_ = Prove(c, a, qPrime)

}
