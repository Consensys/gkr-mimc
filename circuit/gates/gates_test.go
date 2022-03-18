package gates

import (
	"testing"

	"github.com/consensys/gkr-mimc/circuit"
	"github.com/consensys/gkr-mimc/common"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/stretchr/testify/assert"
)

func genericTest(t *testing.T, gate circuit.Gate) {

	size := 10

	l := common.RandomFrArray(size)
	r := common.RandomFrArray(size)

	resA := make([]fr.Element, size)
	resB := make([]fr.Element, size)

	gate.EvalBatch(resA, l, r)

	for i := range resB {
		gate.Eval(&resB[i], &l[i], &r[i])
	}

	assert.Equal(t, resA, resB)
}

func TestGates(t *testing.T) {
	gates := []circuit.Gate{
		IdentityGate{},
		NewCipherGate(fr.NewElement(25)),
	}

	for _, gate := range gates {
		genericTest(t, gate)
	}
}
