package sumcheck2

import (
	"fmt"
	"testing"

	"github.com/consensys/gkr-mimc/circuit"
	"github.com/consensys/gkr-mimc/circuit/gates"
	"github.com/consensys/gkr-mimc/common"
	"github.com/consensys/gkr-mimc/polynomial"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/stretchr/testify/assert"
)

func initializeSumcheckInstance(bN int) (L, R polynomial.BookKeepingTable, qPrime []fr.Element, gate circuit.Gate) {

	q := make([]fr.Element, bN)
	for i := range q {
		q[i].SetUint64(2)
	}

	L = make([]fr.Element, 1<<bN)
	R = make([]fr.Element, 1<<bN)

	for i := range L {
		L[i].SetUint64(uint64(i))
		R[i].SetUint64(uint64(i))
	}

	return polynomial.NewBookKeepingTable(L),
		polynomial.NewBookKeepingTable(R),
		q, gates.NewCipherGate(fr.NewElement(1632134))
}

func TestSumcheck(t *testing.T) {
	bn := 10
	L, R, qPrime, gate := initializeSumcheckInstance(bn)

	instance := instance{L: L, R: R, Eq: make(polynomial.BookKeepingTable, 1<<bn), gate: gate, degree: 8}

	// Test that the degree set is the right one
	{
		_instance := makeInstance(L, R, gate)
		assert.Equal(t, instance.L, _instance.L, "instance do not match")
		assert.Equal(t, instance.R, _instance.R, "instance do not match")
		assert.Equal(t, instance.Eq, _instance.Eq, "instance do not match")
		assert.Equal(t, instance.gate, _instance.gate, "instance do not match")
		assert.Equal(t, instance.degree, _instance.degree, "instance do not match")
	}

	instance.Eq = polynomial.GetFoldedEqTable(qPrime, instance.Eq)
	claim := instance.Evaluation()

	proof, challenges, fClm := Prove(L, R, qPrime, gate)
	valid, challengesV, expectedValue := Verify(claim, proof)

	assert.Equal(t, challenges, challengesV, "prover's and verifier challenges do not match")
	assert.True(t, valid, "sumcheck was not deemed valid")

	var expectedValueP fr.Element
	gate.Eval(&expectedValueP, &fClm[0], &fClm[1])
	expectedValue.Mul(&expectedValueP, &fClm[2])
	assert.Equal(t, expectedValue, expectedValueP, "inconsistency of the final values for the verifier")

}

func BenchmarkSumcheck(b *testing.B) {
	bn := 22
	b.Run(fmt.Sprintf("sumcheck-bn-%v", bn), func(b *testing.B) {
		common.ProfileTrace(b, false, false, func() {
			for c_ := 0; c_ < b.N; c_++ {
				b.StopTimer()
				L, R, qPrime, gate := initializeSumcheckInstance(bn)
				b.StartTimer()
				_, _, _ = Prove(L, R, qPrime, gate)
			}
			b.StopTimer()
		})
	})
}
