package sumcheck

import (
	"fmt"
	"runtime"
	"testing"

	"github.com/consensys/gkr-mimc/common"

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
	mTProof, mQPrime, mQL, mQR, mFClaim := mTProver.Prove(1)
	sTProof, sQPrime, sQL, sQR, sFClaim := sTProver.Prove()

	// Compare their proofs
	assert.Equal(t, sQL, mQL, "Bad qL")
	assert.Equal(t, sQR, mQR, "Bad qR")
	assert.Equal(t, sQPrime, mQPrime, "Bad qPrime")
	assert.Equal(t, sFClaim, mFClaim, "Bad final claim")
	assert.Equal(t, sTProof, mTProof, "Bad proof")

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
	nChunk := 128
	nCore := runtime.GOMAXPROCS(0)

	for _, bN := range bNs {
		b.Run(fmt.Sprintf("bN=%d", bN), func(b *testing.B) {
			benchmarkFullSumcheckMultiThreaded(b, bN, nChunk, nCore, false, false)
		})
	}
}
