package gates

import (
	"testing"

	"github.com/consensys/gkr-mimc/circuit"
	"github.com/consensys/gkr-mimc/common"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/stretchr/testify/assert"
)

func TestAdd(t *testing.T) {
	testGate(t, AddGate{})
}

func TestMul(t *testing.T) {
	testGate(t, MulGate{})
}

func TestCipher(t *testing.T) {
	var ark fr.Element
	ark.SetRandom()
	testGate(t, NewCipherGate(ark))
}

func TestCopy(t *testing.T) {
	testGate(t, CopyGate{})
}

// Generic test case for all gates
func testGate(t *testing.T, gate circuit.Gate) {

	size := 16
	vRs := common.RandomFrArray(size)
	vLs := common.RandomFrArray(size)

	for i := range vRs {
		evalManyVL := make([]fr.Element, size)
		gate.EvalManyVL(evalManyVL, vLs, &vRs[i])

		for j := range vLs {
			var eval fr.Element
			gate.Eval(&eval, &vLs[j], &vRs[i])

			assert.Equal(
				t, eval.String(), evalManyVL[j].String(),
				"Failed at L=%v R=%v vL=%v vR=%v",
				j, i, vLs[j].String(), vRs[i].String(),
			)
		}
	}

	for i := range vLs {
		evalManyVR := make([]fr.Element, size)
		gate.EvalManyVR(evalManyVR, &vLs[i], vRs)

		for j := range vRs {
			var eval fr.Element
			gate.Eval(&eval, &vLs[i], &vRs[j])

			assert.Equal(
				t, eval.String(), evalManyVR[j].String(),
				"Failed at L=%v R=%v vL=%v vR=%v",
				j, i, vLs[i].String(), vRs[j].String(),
			)
		}
	}

}
