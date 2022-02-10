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

	L = makeLargeFrSlice(1 << bN)
	R = makeLargeFrSlice(1 << bN)

	for i := range L {
		L[i].SetUint64(uint64(i))
		R[i].SetUint64(uint64(i))
	}

	return polynomial.NewBookKeepingTable(L),
		polynomial.NewBookKeepingTable(R),
		q, gates.NewCipherGate(fr.NewElement(1632134))
}

func TestFolding(t *testing.T) {
	for bn := 2; bn < 15; bn++ {
		L, R, qPrime, gate := initializeSumcheckInstance(bn)
		instance := makeInstance(L, R, gate)

		callback := make(chan []fr.Element, 100000)

		// Test that the Eq function agrees
		dispatchEqTable(instance, qPrime, callback)
		eqBis := make(polynomial.BookKeepingTable, len(L))
		eqBis = polynomial.GetFoldedEqTable(qPrime, eqBis)

		assert.Equal(t, common.FrSliceToString(eqBis), makeLargeFrSlice(1<<bn), "eq tables do not match after being prefolded")

		// Test that the folding agrees
		dispatchFolding(instance, qPrime[0], callback)
		eqBis.Fold(qPrime[0])

		assert.Equal(t, common.FrSliceToString(eqBis), makeLargeFrSlice(1<<bn), "eq tables do not match after folding")

		dumpInLargePool(instance.L)
		dumpInLargePool(instance.R)
		dumpInLargePool(instance.Eq)
		dumpInLargePool(eqBis)
	}
}

func TestSumcheck(t *testing.T) {

	for bn := 0; bn < 15; bn++ {
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
		challengesV, expectedValue, err := Verify(claim, proof)

		assert.NoErrorf(t, err, "sumcheck was not deemed valid %v", err)
		assert.Equal(t, challenges, challengesV, "prover's and verifier challenges do not match")

		var expVal fr.Element

		gate.Eval(&expVal, &fClm[0], &fClm[1])
		expVal.Mul(&expVal, &fClm[2])
		assert.Equal(t, expectedValue.String(), expVal.String(), "inconsistency of the final values for the verifier")
	}

}

func BenchmarkSumcheck(b *testing.B) {
	bn := 22
	b.Run(fmt.Sprintf("sumcheck-bn-%v", bn), func(b *testing.B) {
		common.ProfileTrace(b, false, true, func() {
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
