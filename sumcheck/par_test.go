package sumcheck

import (
	"fmt"
	"gkr-mimc/common"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMultiThreaded(t *testing.T) {
	// General parameters of the test
	bN := 8
	nChunks := 4 // nChunks < 2 ** bN

	// Compare the multi-threaded and the single threaded prover
	mTProver := InitializeMultiThreadedProver(bN, nChunks)
	sTProver := InitializeProverForTests(bN)

	// Compare both provers on the claims
	mTClaim := mTProver.GetClaim(3)
	mTClaim1 := mTProver.GetClaim(1)
	sTClaim := sTProver.GetClaim()
	assert.Equal(t, sTClaim, mTClaim, "Error in get claim")
	assert.Equal(t, sTClaim, mTClaim1, "Error in get claim")

	// Run both prover and compare their outputs
	mTProof, _, _, _, _ := mTProver.Prove(1)
	sTProof, _, _, _, _ := sTProver.Prove()

	// Compare their proofs
	assert.Equal(t, len(sTProof.PolyCoeffs), len(mTProof.PolyCoeffs), "Bad proof length")
	for k := range mTProof.PolyCoeffs {
		assert.Equal(t,
			len(sTProof.PolyCoeffs[k]),
			len(mTProof.PolyCoeffs[k]),
			"Bad proof length at k = %v", k,
		)
		for l := range mTProof.PolyCoeffs[k] {
			assert.Equal(t,
				sTProof.PolyCoeffs[k][l],
				mTProof.PolyCoeffs[k][l],
				"Bad proof at k = %v, l=%v", k, l,
			)
		}
	}

	verifier := Verifier{}
	valid, _, _, _, _ := verifier.Verify(mTClaim, mTProof, 1, 1)
	assert.True(t, valid, "Verifier failed")
}

func benchmarkFullSumcheckMultiThreaded(b *testing.B, bN, nChunks, nCore int, profiled, traced bool) {
	b.ResetTimer()
	for _count := 0; _count < b.N; _count++ {
		prover := InitializeMultiThreadedProver(bN, nChunks)
		common.ProfileTrace(b, profiled, traced,
			func() {
				prover.Prove(nChunks)
			},
		)
	}
}

func BenchmarkSumcheckMultiThreaded(b *testing.B) {
	bNs := [1]int{20}
	nChunk := 8
	nCore := runtime.GOMAXPROCS(0)

	for _, bN := range bNs {
		b.Run(fmt.Sprintf("bN=%d", bN), func(b *testing.B) {
			benchmarkFullSumcheckMultiThreaded(b, bN, nChunk, nCore, false, false)
		})
	}
}
