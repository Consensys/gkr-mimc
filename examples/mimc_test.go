package examples

import (
	"fmt"
	"gkr-mimc/common"
	"gkr-mimc/gkr"
	"gkr-mimc/hash"
	"gkr-mimc/sumcheck"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/consensys/gurvy/bn256/fr"
)

func TestMimc(t *testing.T) {

	// Initialize the circuit
	circuit := CreateMimcCircuit()
	// We test on the hashing of 0
	// This checks the transition functions to be consistent
	// With the actual hash function

	// Test the consistency between the the combinator and the transition function
	bN := 3
	var zero, one fr.Element
	one.SetOne()
	expectedOutputs := make([]fr.Element, 1)

	hash.MimcPermutationInPlace(&expectedOutputs[0], zero)
	// Computes the actual outputs using the GenerateAssignment function
	inputs := make([]fr.Element, 2*(1<<bN))
	assignment := circuit.GenerateAssignment(inputs)
	actualOutputs := assignment.LayerAsBKTNoCopy(91).Table
	// An error here indicate an error in the transition functions definition
	assert.Equal(t, expectedOutputs[0], actualOutputs[0], "Error on the state calculation")

	layer1 := assignment.LayerAsBKTNoCopy(1).Table
	gates := circuit.Gates(0)
	layer1FromCombinator := []fr.Element{
		sumcheck.EvaluateCombinator(zero, zero, one, gates, []fr.Element{one, zero}),
		sumcheck.EvaluateCombinator(zero, zero, one, gates, []fr.Element{zero, one}),
	}
	// An error here indicate an error in the combinator definition
	assert.Equal(t, layer1[0], layer1FromCombinator[0], "Error on cipher")
	assert.Equal(t, layer1[1<<bN], layer1FromCombinator[1], "Error on copy")

	ptest := gkr.NewProver(circuit, assignment)
	qPrime := make([]fr.Element, bN)
	if bN > 0 {
		qPrime[0].SetOne()
	}

	// Get the sumcheck provers for the first layer on q = 0 and q = 1
	// And test that the claims are consistent with the assignment in layer 1
	sumcheckPQ0 := ptest.IntermediateRoundsSumcheckProver(0, qPrime, []fr.Element{zero}, []fr.Element{zero}, one, zero)
	sumcheckPQ1 := ptest.IntermediateRoundsSumcheckProver(0, qPrime, []fr.Element{one}, []fr.Element{zero}, one, zero)
	claimQ0 := sumcheckPQ0.GetClaim()
	claimQ1 := sumcheckPQ1.GetClaim()
	// If the test fails there, there is likely a problem with the tables
	assert.Equal(t, layer1[0], claimQ0, "Error with the claims")
	assert.Equal(t, layer1[1<<bN], claimQ1, "Error with the claims")

	// Get the sumcheck provers for the last layer on q = 0 and q = 1
	// And test that the claims are consistent with the assignment in layer n-1
	sumcheckPQInit := ptest.InitialRoundSumcheckProver(qPrime, []fr.Element{})
	claimQInit := sumcheckPQInit.GetClaim()
	// If the test fails there, there is likely a problem with the tables
	assert.Equal(t, actualOutputs[0], claimQInit, "Error with the claims")

	// Finally checks the entire GKR protocol
	prover := gkr.NewProver(circuit, assignment)
	proof := prover.Prove(1)
	verifier := gkr.NewVerifier(bN, circuit)
	valid := verifier.Verify(proof, actualOutputs, inputs)
	// An error here mostly indicate a problem with the degree calculator
	assert.True(t, valid, "GKR verifier refused")
}

var _mimcProof gkr.Proof

func benchmarkMIMCCircuit(b *testing.B, bN, nCore, minChunkSize int, profiled, traced bool) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		// Initialize the circuit
		circuit := CreateMimcCircuit()
		inputs := make([]fr.Element, 1<<(bN+1))
		assignment := circuit.GenerateAssignment(inputs)
		// Finally checks the entire GKR protocol
		prover := gkr.NewProver(circuit, assignment)

		common.ProfileTrace(b, profiled, traced, func() {
			_mimcProof = prover.Prove(nCore)
		})
	}
}

func BenchmarkMimcCircuit(b *testing.B) {
	bNs := [...]int{15, 16, 17, 18}
	for _, bN := range bNs {
		b.Run(fmt.Sprintf("bN=%d", bN), func(b *testing.B) {
			nCore := runtime.GOMAXPROCS(0)
			benchmarkMIMCCircuit(b, bN, nCore, 1<<9, true, false)
		})
	}
}
