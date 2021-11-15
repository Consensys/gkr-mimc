package examples

import (
	"fmt"
	"runtime"
	"sync"
	"testing"

	"github.com/consensys/gkr-mimc/circuit"
	"github.com/consensys/gkr-mimc/common"
	"github.com/consensys/gkr-mimc/gkr"
	"github.com/consensys/gkr-mimc/hash"
	"github.com/stretchr/testify/assert"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

func randomInputs(nChunks, bN int) [][]fr.Element {
	size := 2 * (1 << bN)
	chunkSize := size / nChunks
	res := make([][]fr.Element, nChunks)
	for i := range res {
		res[i] = common.RandomFrArray(chunkSize)
	}
	return res
}

func TestChunkOne(t *testing.T) {
	// Initialize the circuit
	mimcCircuit := CreateMimcCircuit()

	inputs := make([][]fr.Element, 1)
	inputs[0] = make([]fr.Element, 32)

	for i := 0; i < 10; i++ {
		inputs[0][i].SetUint64(uint64(i))
	}

	assignment := mimcCircuit.Assign(inputs, 1)
	outputs := assignment.Values[91]

	q := []fr.Element{}
	qPrime := make([]fr.Element, 4)
	qPrime[0].SetString("12674017531719144457961514489412020155949820310579084257497356610663280697266")
	qPrime[1].SetString("15680445612855895897639426799393555724157944733839973003296739765452665576581")
	qPrime[2].SetString("20103910461169496479178391262760032563004404394843160487237343404104208642606")
	qPrime[3].SetString("17694881679643180392697529697365820333255860254082315016447853956318621618728")

	prover := gkr.NewProver(mimcCircuit, assignment)
	proof := prover.Prove(1, qPrime, q)

	// fmt.Printf("Output = %v \n", common.FrSliceToString(outputs[0]))

	verifier := gkr.NewVerifier(4, mimcCircuit)
	valid := verifier.Verify(proof, inputs, outputs, qPrime, q)

	assert.Truef(t, valid, "Verifier did not pass")
}

func TestMimc(t *testing.T) {

	// Initialize the circuit
	mimcCircuit := CreateMimcCircuit()

	// This checks the transition functions to be consistent
	// With the actual hash function

	// Test the consistency between the the combinator and the transition function
	bN := 3
	nChunks := 2
	inputChunkSize := 2 * (1 << bN) / nChunks
	var zero, one fr.Element
	one.SetOne()

	// Performs the assignment
	inputs := randomInputs(nChunks, bN)
	assignment := mimcCircuit.Assign(inputs, 1)
	outputs := assignment.Values[91]

	// Sees if the output is consistent with the result of calling Mimc permutation
	newState := inputs[0][inputChunkSize/2]
	block := inputs[0][0]
	oldState := inputs[0][inputChunkSize/2]
	// Our circuit expects the first addition to be made by the client
	block.Sub(&block, &oldState)
	hash.MimcPermutationInPlace(&newState, block)
	// An error here indicate an error in the transition functions definition
	assert.Equal(t, newState.String(), outputs[0][0].String(), "Error on the state calculation")

	layer1 := assignment.Values[1]
	gates := mimcCircuit.Layers[0].Gates
	layer1FromCombinator := []fr.Element{
		// Expected to output the value of copy
		circuit.EvaluateCombinator(
			&inputs[0][inputChunkSize/2], &inputs[0][0], &one, gates, []fr.Element{one, zero},
		),
		// Expected to output the value of cipher
		circuit.EvaluateCombinator(
			&inputs[0][inputChunkSize/2], &inputs[0][0], &one, gates, []fr.Element{zero, one},
		),
	}
	// An error here indicate an error in the combinator definition
	assert.Equal(t, layer1[0][0], layer1FromCombinator[0], "Error on cipher")
	assert.Equal(t, layer1[0][inputChunkSize/2], layer1FromCombinator[1], "Error on copy")

	ptest := gkr.NewProver(mimcCircuit, assignment)
	qPrime := make([]fr.Element, bN)

	// Get the sumcheck provers for the first layer on q = 0 and q = 1
	// And test that the claims are consistent with the assignment in layer 1
	sumcheckPQ0 := ptest.IntermediateRoundsSumcheckProver(0, qPrime, []fr.Element{zero}, []fr.Element{zero}, one, zero, 1)
	sumcheckPQ1 := ptest.IntermediateRoundsSumcheckProver(0, qPrime, []fr.Element{one}, []fr.Element{zero}, one, zero, 1)
	claimQ0 := sumcheckPQ0.GetClaim(1)
	claimQ1 := sumcheckPQ1.GetClaim(1)
	// If the test fails there, there is likely a problem with the tables
	assert.Equal(t, layer1[0][0], claimQ0, "Error with the claims")
	assert.Equal(t, layer1[0][inputChunkSize/2], claimQ1, "Error with the claims")

	// Get the sumcheck provers for the last layer on q = 0
	// And test that the claims are consistent with the assignment in layer n-1
	sumcheckPQInit := ptest.InitialRoundSumcheckProver(qPrime, []fr.Element{}, 1)
	claimQInit := sumcheckPQInit.GetClaim(1)
	// If the test fails there, there is likely a problem with the tables
	assert.Equal(t, outputs[0][0], claimQInit, "Error with the claims")

	// Finally checks the entire GKR protocol
	prover := gkr.NewProver(mimcCircuit, assignment)
	proof := prover.Prove(1, []fr.Element{}, []fr.Element{})
	verifier := gkr.NewVerifier(bN, mimcCircuit)
	valid := verifier.Verify(proof, inputs, outputs, []fr.Element{}, []fr.Element{})
	// An error here mostly indicate a problem with the degree calculator
	assert.True(t, valid, "GKR verifier refused")
}

var _mimcProof gkr.Proof

func benchmarkMIMCCircuit(b *testing.B, bN, nCore, nChunks int, profiled, traced bool) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		// Initialize the circuit
		mimcCircuit := CreateMimcCircuit()
		// Performs the assignment
		inputs := randomInputs(nChunks, bN)
		assignment := mimcCircuit.Assign(inputs, 1)
		// Finally checks the entire GKR protocol
		prover := gkr.NewProver(mimcCircuit, assignment)

		common.ProfileTrace(b, profiled, traced, func() {
			_mimcProof = prover.Prove(nCore, []fr.Element{}, []fr.Element{})
		})
	}
}

func benchmarkMIMCGKRProverMultiProcess(b *testing.B, bN, nProcesses, nCore, nChunks int, profiled, traced bool) {

	b.ResetTimer()
	b.StopTimer()
	for _b := 0; _b < b.N; _b++ {
		var wgReady, wgGo, wgDone sync.WaitGroup
		wgReady.Add(nProcesses)
		wgGo.Add(1)
		wgDone.Add(nProcesses)
		for k := 0; k < nProcesses; k++ {
			go func() {
				nCore := nCore / nProcesses
				nChunks := nChunks / nProcesses
				bN := bN - common.Log2Ceil(nProcesses)
				// Redimensionate bN to take into account the
				// Initialize the circuit
				mimcCircuit := CreateMimcCircuit()
				// Performs the assignment
				inputs := randomInputs(nChunks, bN)
				assignment := mimcCircuit.Assign(inputs, nCore)
				// Finally checks the entire GKR protocol
				prover := gkr.NewProver(mimcCircuit, assignment)
				wgReady.Done()
				wgGo.Wait() // Wait for the main thread's signal
				_mimcProof = prover.Prove(nCore, []fr.Element{}, []fr.Element{})
				wgDone.Done()
			}()
		}
		wgReady.Wait()

		b.StartTimer()
		common.ProfileTrace(b, profiled, traced, func() {
			wgGo.Done() // Gives the signal
			wgDone.Wait()
		})
		b.StopTimer()
	}

}

func BenchmarkMimcGKRProver(b *testing.B) {
	nChunks := common.GetNChunks()
	bN := common.GetBN()
	nCore := runtime.GOMAXPROCS(0)
	profiled := common.GetProfiled()
	traced := common.GetTraced()
	b.Run(fmt.Sprintf("bN=%d-nCore", bN), func(b *testing.B) {
		benchmarkMIMCCircuit(b, bN, nCore, nChunks, profiled, traced)
	})
}

func BenchmarkMimcGKRProverMultiProcess(b *testing.B) {
	nChunks := common.GetNChunks()
	bN := common.GetBN()
	nCore := runtime.GOMAXPROCS(0)
	nProcesses := common.GetNProcesses()
	profiled := common.GetProfiled()
	traced := common.GetTraced()
	b.Run(fmt.Sprintf("bN=%d-nCore", bN), func(b *testing.B) {
		benchmarkMIMCGKRProverMultiProcess(b, bN, nProcesses, nCore, nChunks, profiled, traced)
	})
}
