package sumcheck

import (
	"fmt"
	"runtime"
	"testing"

	"github.com/consensys/gkr-mimc/circuit"
	"github.com/consensys/gkr-mimc/common"
	"github.com/consensys/gkr-mimc/poly"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/stretchr/testify/assert"
)

func TestFolding(t *testing.T) {
	for bn := 2; bn < 15; bn++ {
		X, _, qPrime, gate := InitializeCipherGateInstance(bn)
		instance := makeInstance(X, gate)

		callback := make(chan []fr.Element, 100000)

		// Test that the Eq function agrees
		dispatchEqTable(instance, qPrime[0], callback)
		eqBis := poly.MakeLarge(len(X[0]))
		eqBis = poly.FoldedEqTable(eqBis, qPrime[0])

		assert.Equal(t, eqBis.String(), instance.Eq.String(), "eq tables do not match after being prefolded")

		// Test that the folding agrees
		dispatchFolding(instance, qPrime[0][0], callback)
		eqBis.Fold(qPrime[0][0])

		assert.Equal(t, eqBis.String(), instance.Eq.String(), "eq tables do not match after folding")

		poly.DumpLarge(X[0])
		poly.DumpLarge(X[1])
		poly.DumpLarge(instance.Eq)
		poly.DumpLarge(eqBis)
	}
}

func genericTest(t *testing.T, X []poly.MultiLin, claims []fr.Element, qs [][]fr.Element, gate circuit.Gate) {

	instance := makeInstance(X, gate)

	// Then initializes the eq table
	rnd := makeEqTable(instance, claims, qs, nil)
	claimTest := Evaluation(gate, qs, claims, X...)

	if !rnd.IsZero() {
		eval := poly.EvalUnivariate(claims, rnd)

		if eval != claimTest {
			panic(fmt.Sprintf("the random linear combination did not match de claim %v != %v \nthe claims are %v\nrecomb chal is %v",
				claimTest.String(), eval.String(), common.FrSliceToString(claims), rnd.String()))
		}
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
	for bn := 0; bn < 15; bn++ {
		ninstance := 10
		X, claims, qs, gate := InitializeMultiInstance(bn, ninstance)
		genericTest(t, X, claims, qs, gate)
	}
}

func TestWithCipherGate(t *testing.T) {

	for bn := 0; bn < 15; bn++ {
		X, claims, qs, gate := InitializeCipherGateInstance(bn)
		genericTest(t, X, claims, qs, gate)
	}
}

func BenchmarkWithCipherGate(b *testing.B) {
	bn := 22
	b.Run(fmt.Sprintf("sumcheck-bn-%v", bn), func(b *testing.B) {
		common.ProfileTrace(b, false, false, func() {
			for c_ := 0; c_ < b.N; c_++ {
				b.StopTimer()
				X, claims, qPrime, gate := InitializeCipherGateInstance(bn)
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
				X, claims, qPrime, gate := InitializeMultiInstance(bn, nInstance)
				b.StartTimer()
				_, _, _ = Prove(X, qPrime, claims, gate)
			}
			b.StopTimer()
		})
	})
}

func BenchmarkPartialEvalWithCipher(b *testing.B) {
	bn := 15
	b.Run(fmt.Sprintf("sumcheck-bn-%v", bn), func(b *testing.B) {
		common.ProfileTrace(b, true, false, func() {

			// Prepare the benchmark
			X, claims, qPrime, gate := InitializeCipherGateInstance(bn)
			inst := makeInstance(X, gate)
			callback := make(chan []fr.Element, 8*runtime.NumCPU())
			makeEqTable(inst, claims, qPrime, callback)

			b.ResetTimer()
			for c_ := 0; c_ < b.N; c_++ {
				for _i := 0; _i < 30000; _i++ {
					dispatchPartialEvals(inst, callback)
				}
			}
			b.StopTimer()
		})
	})
}
