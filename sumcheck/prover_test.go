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

func initializeCipherGateInstance(bn int) (X []poly.MultiLin, claims []fr.Element, qPrime [][]fr.Element, gate circuit.Gate) {

	q := make([]fr.Element, bn)
	for i := range q {
		q[i].SetUint64(2)
	}

	gate = gates.NewCipherGate(fr.NewElement(1632134))

	L := poly.MakeLargeFrSlice(1 << bn)
	R := poly.MakeLargeFrSlice(1 << bn)

	for i := range L {
		L[i].SetUint64(uint64(i))
		R[i].SetUint64(uint64(i))
	}

	inst_ := instance{
		X:      []poly.MultiLin{L, R},
		gate:   gate,
		degree: gate.Degree() + 1,
		Eq:     poly.MakeLargeFrSlice(1 << bn),
	}
	poly.FoldedEqTable(inst_.Eq, q)
	claim := inst_.Evaluation()

	return []poly.MultiLin{L, R}, []fr.Element{claim}, [][]fr.Element{q}, gate
}

func initializeMultiInstance(bn, ninstance int) (X []poly.MultiLin, claims []fr.Element, qPrime [][]fr.Element, gate circuit.Gate) {

	n := 1 << bn
	gate = gates.IdentityGate{}

	// Create the qs
	qs := make([][]fr.Element, ninstance)
	for i := range qs {
		q := make([]fr.Element, bn)
		for j := range q {
			q[j].SetUint64(uint64(i*j + i))
		}
		qs[i] = q
	}

	L := poly.MakeLargeFrSlice(n)
	R := poly.MakeLargeFrSlice(n)

	for i := range L {
		L[i].SetUint64(uint64(i))
		R[i].SetUint64(uint64(i))
	}

	inst_ := instance{X: []poly.MultiLin{L, R}, gate: gate, degree: gate.Degree() + 1, Eq: poly.MakeLargeFrSlice(n)}

	claims = make([]fr.Element, ninstance)
	for i := range claims {
		poly.FoldedEqTable(inst_.Eq, qs[i])
		claims[i] = inst_.Evaluation()
	}

	return []poly.MultiLin{L, R}, claims, qs, gate
}

func TestFolding(t *testing.T) {
	for bn := 2; bn < 15; bn++ {
		X, _, qPrime, gate := initializeCipherGateInstance(bn)
		instance := makeInstance(X, gate)

		callback := make(chan []fr.Element, 100000)

		// Test that the Eq function agrees
		dispatchEqTable(instance, qPrime[0], callback)
		eqBis := poly.MakeLargeFrSlice(len(X[0]))
		eqBis = poly.FoldedEqTable(eqBis, qPrime[0])

		assert.Equal(t, common.FrSliceToString(eqBis), common.FrSliceToString(instance.Eq), "eq tables do not match after being prefolded")

		// Test that the folding agrees
		dispatchFolding(instance, qPrime[0][0], callback)
		eqBis.Fold(qPrime[0][0])

		assert.Equal(t, common.FrSliceToString(eqBis), common.FrSliceToString(instance.Eq), "eq tables do not match after folding")

		poly.DumpInLargePool(X[0])
		poly.DumpInLargePool(X[1])
		poly.DumpInLargePool(instance.Eq)
		poly.DumpInLargePool(eqBis)
	}
}

func genericTest(t *testing.T, X []poly.MultiLin, claims []fr.Element, qs [][]fr.Element, gate circuit.Gate) {

	instance := makeInstance(X, gate)

	// Then initializes the eq table
	rnd := makeEqTable(instance, claims, qs, nil)
	claimTest := instance.Evaluation()

	if !rnd.IsZero() {
		eval := poly.EvalUnivariate(claims, rnd)
		assert.Equal(t, claimTest.String(), eval.String(), "the random linear combination did not match de claim")
	}

	proof, challenges, fClm := Prove(X, qs, claims, gate)
	challengesV, expectedValue, recombChal, err := Verify(claims, proof)

	assert.NoErrorf(t, err, "sumcheck was not deemed valid %v", err)
	assert.Equal(t, challenges, challengesV, "prover's and verifier challenges do not match")
	assert.Equal(t, rnd, recombChal, "recombination challenges do not match")

	var expVal fr.Element

	// Makes an array of pointer from the array
	ptrArr := make([]*fr.Element, len(fClm)-1)
	for k := range ptrArr {
		ptrArr[k] = &fClm[k+1]
	}

	gate.Eval(&expVal, ptrArr...)
	expVal.Mul(&expVal, &fClm[0])
	assert.Equal(t, expectedValue.String(), expVal.String(), "inconsistency of the final values for the verifier")

}

func TestWithMultiIdentity(t *testing.T) {
	bn, ninstance := 5, 10
	X, claims, qs, gate := initializeMultiInstance(bn, ninstance)

	genericTest(t, X, claims, qs, gate)

}

func TestWithCipherGate(t *testing.T) {

	for bn := 0; bn < 15; bn++ {
		X, claims, qs, gate := initializeCipherGateInstance(bn)
		genericTest(t, X, claims, qs, gate)
	}

}

func BenchmarkWithCipherGate(b *testing.B) {
	bn := 22
	b.Run(fmt.Sprintf("sumcheck-bn-%v", bn), func(b *testing.B) {
		common.ProfileTrace(b, false, true, func() {
			for c_ := 0; c_ < b.N; c_++ {
				b.StopTimer()
				X, claims, qPrime, gate := initializeCipherGateInstance(bn)
				b.StartTimer()
				_, _, _ = Prove(X, qPrime, claims, gate)
			}
			b.StopTimer()
		})
	})
}

func BenchmarkMultiIdentity(b *testing.B) {
	bn := 22
	nInstance := 91
	b.Run(fmt.Sprintf("sumcheck-bn-%v", bn), func(b *testing.B) {
		common.ProfileTrace(b, false, true, func() {
			for c_ := 0; c_ < b.N; c_++ {
				b.StopTimer()
				X, claims, qPrime, gate := initializeMultiInstance(bn, nInstance)
				b.StartTimer()
				_, _, _ = Prove(X, qPrime, claims, gate)
			}
			b.StopTimer()
		})
	})
}
