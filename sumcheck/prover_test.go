package sumcheck

import (
	"fmt"
	"gkr-mimc/circuit"
	"gkr-mimc/common"
	"gkr-mimc/polynomial"
	"testing"

	"github.com/consensys/gurvy/bn256/fr"
	"github.com/stretchr/testify/assert"
)

func TestGetEvals(t *testing.T) {
	var zero, one, two, three, four, twelve, minusEight fr.Element
	one.SetOne()
	two.SetUint64(2)
	three.SetUint64(3)
	four.SetUint64(4)
	twelve.SetUint64(12)
	minusEight.SetUint64(8)
	minusEight.Neg(&minusEight)

	// Simulate a prefolding with q', q = 1, {}
	v := []fr.Element{zero, one, two, three}
	add := []fr.Element{zero, zero, one, zero}
	eQ := []fr.Element{zero, one}

	vLTable := polynomial.NewBookKeepingTable(v)
	vRTable := vLTable.DeepCopy()
	eQTable := polynomial.NewBookKeepingTable(eQ)
	addTable := polynomial.NewBookKeepingTable(add)

	prover := NewSingleThreadedProver(vLTable, vRTable, eQTable, []circuit.Gate{circuit.AddGate{}}, []polynomial.BookKeepingTable{addTable})

	claim := prover.GetClaim()
	assert.Equal(t, claim, four, "Error on get claims")

	// Check the evaluations on hL
	evals := prover.GetEvalsOnHL()
	assert.Equal(t, evals[0], zero, "Error on GetEvalsOnHL")
	assert.Equal(t, evals[1], four, "Error on GetEvalsOnHL")
	assert.Equal(t, evals[2], twelve, "Error on GetEvalsOnHL")
	// Fold on one
	prover.FoldHL(one)

	// Check the evaluations on hR
	evals = prover.GetEvalsOnHR()
	assert.Equal(t, evals[0], four, "Error on GetEvalsOnHR")
	assert.Equal(t, evals[1], zero, "Error on GetEvalsOnHR")
	assert.Equal(t, evals[2], minusEight, "Error on GetEvalsOnHR")
	// Fold on zero
	prover.FoldHR(zero)

	// Check the evaluations on hPrime
	evals = prover.GetEvalsOnHPrime()
	assert.Equal(t, evals[0], zero, "Error on GetEvalsOnHPrime")
	assert.Equal(t, evals[1], four, "Error on GetEvalsOnHPrime")
	assert.Equal(t, evals[2], twelve, "Error on GetEvalsOnHPrime")
}

func TestSumcheck(t *testing.T) {
	var zero, one, two, three fr.Element
	one.SetOne()
	two.SetUint64(2)
	three.SetUint64(3)

	// Simulate a prefolding with q', q = 1, {}
	v := []fr.Element{zero, one, two, three}
	add := []fr.Element{zero, zero, one, zero}
	eQ := []fr.Element{zero, one}

	// Creates the tables
	vLTable := polynomial.NewBookKeepingTable(v)
	vRTable := vLTable.DeepCopy()
	vForEval := vLTable.DeepCopy()
	eQTable := polynomial.NewBookKeepingTable(eQ)
	eQForEvals := eQTable.DeepCopy()
	addTable := polynomial.NewBookKeepingTable(add)
	addForEval := addTable.DeepCopy()

	// Check that the prover and the verifier are on-par
	prover := NewSingleThreadedProver(vLTable, vRTable, eQTable, []circuit.Gate{circuit.AddGate{}}, []polynomial.BookKeepingTable{addTable})
	claim := prover.GetClaim()
	proof, expectedQPrime, expectedQL, expectedQR, subClaims := prover.Prove()
	verifier := Verifier{}
	valid, qPrime, qL, qR, finalClaim := verifier.Verify(claim, proof, 1, 1)
	assert.True(t, valid, "Sumcheck verification failed")
	assert.Equal(t, expectedQPrime[0], qPrime[0], "Mismatch on qPrime")
	assert.Equal(t, expectedQL[0], qL[0], "Mismatch on qL")
	assert.Equal(t, expectedQR[0], qR[0], "Mismatch on qR")

	// Compares the prover's subclaims against the initial table values
	finalVL, finalVR := vForEval.EvaluateLeftAndRight(qPrime, qL, qR)
	finalEq := eQForEvals.Evaluate(qPrime)
	finalAdd := addForEval.Evaluate(append(qL, qR...))
	assert.Equal(t, finalVL, subClaims[0], "Mismatch on claims")
	assert.Equal(t, finalVR, subClaims[1], "Mismatch on claims")
	assert.Equal(t, finalEq, subClaims[2], "Mismatch on claims")
	assert.Equal(t, finalAdd, subClaims[3], "Mismatch on claims")

	var actualFinalClaim fr.Element
	circuit.AddGate{}.Eval(&actualFinalClaim, finalVL, finalVR)
	actualFinalClaim.Mul(&actualFinalClaim, &finalAdd)
	actualFinalClaim.Mul(&actualFinalClaim, &finalEq)
	assert.Equal(t, finalClaim, actualFinalClaim, "Mismatch on the final claim")

}

func TestBenchmarkSetup(t *testing.T) {
	prover := InitializeProverForTests(1)
	claim := prover.GetClaim()
	proof, _, _, _, _ := prover.Prove()
	verifier := Verifier{}
	valid, _, _, _, _ := verifier.Verify(claim, proof, 1, 1)
	assert.True(t, valid, "Verifier failed")
}

func benchmarkFullSumcheckProver(b *testing.B, bN int, profiled, traced bool) {
	b.ResetTimer()
	for _count := 0; _count < b.N; _count++ {
		prover := InitializeProverForTests(bN)
		common.ProfileTrace(b, profiled, traced,
			func() {
				prover.Prove()
			},
		)
	}
}

func benchmarkFineGrainedProver(b *testing.B, bN int, profiled, traced bool) {

	var two fr.Element
	two.SetUint64(2)

	if b.N != 1 {
		panic("Call it with N = 1")
	}

	prover := InitializeProverForTests(bN)

	b.Run(fmt.Sprintf("GetEvalsOnHL-bN=%v", bN), func(b *testing.B) {
		common.ProfileTrace(b, profiled, traced,
			func() {
				for i := 0; i < b.N; i++ {
					prover.GetEvalsOnHL()
				}
			})
	})

	prover.FoldHL(two)

	b.Run(fmt.Sprintf("GetEvalsOnHR-bN=%v", bN), func(b *testing.B) {
		common.ProfileTrace(b, profiled, traced,
			func() {
				for i := 0; i < b.N; i++ {
					prover.GetEvalsOnHR()
				}
			})
	})

	prover.FoldHR(two)

	b.Run(fmt.Sprintf("GetEvalsOnHPrime-bN=%v", bN), func(b *testing.B) {
		common.ProfileTrace(b, profiled, traced,
			func() {
				for i := 0; i < b.N; i++ {
					prover.GetEvalsOnHPrime()
				}
			})
	})
}

func BenchmarkSumcheck(b *testing.B) {
	bNs := [1]int{23}

	for _, bN := range bNs {
		b.Run(fmt.Sprintf("bN=%d", bN), func(b *testing.B) {
			benchmarkFullSumcheckProver(b, bN, false, false)
		})
	}
}

func BenchmarkSumcheckFineGrained(b *testing.B) {
	bNs := [1]int{24}

	for _, bN := range bNs {
		// Run the fine grained benchmark
		benchmarkFineGrainedProver(b, bN, false, false)
	}
}
