package sumcheck

import (
	"fmt"
	"testing"

	"github.com/consensys/gkr-mimc/circuit"
	"github.com/consensys/gkr-mimc/circuit/gates"
	"github.com/consensys/gkr-mimc/common"
	"github.com/consensys/gkr-mimc/poly"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/stretchr/testify/assert"
)

func initializeCipherGateTest(bN int) (L, R poly.MultiLin, claim []fr.Element, qPrime [][]fr.Element, gate circuit.Gate) {

	q := make([]fr.Element, bN)
	for i := range q {
		q[i].SetUint64(2)
	}

	L = poly.MakeLargeFrSlice(1 << bN)
	R = poly.MakeLargeFrSlice(1 << bN)

	for i := range L {
		L[i].SetUint64(uint64(i))
		R[i].SetUint64(uint64(i))
	}

	return poly.NewBookKeepingTable(L),
		poly.NewBookKeepingTable(R),
		[]fr.Element{},
		[][]fr.Element{q}, gates.NewCipherGate(fr.NewElement(1632134))
}

func initializeMultiInstance(bn, ninstance int) (L, R poly.MultiLin, claims []fr.Element, qPrime [][]fr.Element, gate circuit.Gate) {

	n := 1 << bn
	gate = gates.CopyGate{}

	// Create the qs
	qs := make([][]fr.Element, ninstance)
	for i := range qs {
		q := make([]fr.Element, bn)
		for j := range q {
			q[j].SetUint64(uint64(i*j + i))
		}
		qs[i] = q
	}

	L = poly.MakeLargeFrSlice(n)
	R = poly.MakeLargeFrSlice(n)

	for i := range L {
		L[i].SetUint64(uint64(i))
		R[i].SetUint64(uint64(i))
	}

	inst_ := instance{L: L, R: R, gate: gate, degree: gate.Degree() + 1, Eq: poly.MakeLargeFrSlice(n)}

	claims = make([]fr.Element, ninstance)
	for i := range claims {
		poly.FoldedEqTable(inst_.Eq, qs[i])
		claims[i] = inst_.Evaluation()
	}

	return L, R, claims, qs, gate
}

func TestFolding(t *testing.T) {
	for bn := 2; bn < 15; bn++ {
		L, R, _, qPrime, gate := initializeCipherGateTest(bn)
		instance := makeInstance(L, R, gate)

		callback := make(chan []fr.Element, 100000)

		// Test that the Eq function agrees
		dispatchEqTable(instance, qPrime[0], callback)
		eqBis := poly.MakeLargeFrSlice(len(L))
		eqBis = poly.FoldedEqTable(eqBis, qPrime[0])

		assert.Equal(t, common.FrSliceToString(eqBis), common.FrSliceToString(instance.Eq), "eq tables do not match after being prefolded")

		// Test that the folding agrees
		dispatchFolding(instance, qPrime[0][0], callback)
		eqBis.Fold(qPrime[0][0])

		assert.Equal(t, common.FrSliceToString(eqBis), common.FrSliceToString(instance.Eq), "eq tables do not match after folding")

		poly.DumpInLargePool(instance.L)
		poly.DumpInLargePool(instance.R)
		poly.DumpInLargePool(instance.Eq)
		poly.DumpInLargePool(eqBis)
	}
}

func genericTest(t *testing.T, L, R poly.MultiLin, claims []fr.Element, qs [][]fr.Element, gate circuit.Gate) {

	instance := makeInstance(L, R, gate)

	// Then initializes the eq table
	rnd := makeEqTable(instance, claims, qs, nil)
	claim := instance.Evaluation()

	if !rnd.IsZero() {
		eval := poly.EvaluatePolynomial(claims, rnd)
		assert.Equal(t, claim.String(), eval.String(), "the random linear combination did not match de claim")
	}

	proof, challenges, fClm := Prove(L, R, qs, claims, gate)
	challengesV, expectedValue, err := Verify(claim, proof)

	assert.NoErrorf(t, err, "sumcheck was not deemed valid %v", err)
	assert.Equal(t, challenges, challengesV, "prover's and verifier challenges do not match")

	var expVal fr.Element

	gate.Eval(&expVal, &fClm[0], &fClm[1])
	expVal.Mul(&expVal, &fClm[2])
	assert.Equal(t, expectedValue.String(), expVal.String(), "inconsistency of the final values for the verifier")

}

func TestMultiIdentity(t *testing.T) {
	bn, ninstance := 5, 10
	L, R, claims, qs, gate := initializeMultiInstance(bn, ninstance)

	genericTest(t, L, R, claims, qs, gate)

}

func TestCipherGate(t *testing.T) {

	for bn := 0; bn < 15; bn++ {
		L, R, claims, qs, gate := initializeCipherGateTest(bn)
		genericTest(t, L, R, claims, qs, gate)
	}

}

func BenchmarkSumcheck(b *testing.B) {
	bn := 22
	b.Run(fmt.Sprintf("sumcheck-bn-%v", bn), func(b *testing.B) {
		common.ProfileTrace(b, false, true, func() {
			for c_ := 0; c_ < b.N; c_++ {
				b.StopTimer()
				L, R, claims, qPrime, gate := initializeCipherGateTest(bn)
				b.StartTimer()
				_, _, _ = Prove(L, R, qPrime, claims, gate)
			}
			b.StopTimer()
		})
	})
}
