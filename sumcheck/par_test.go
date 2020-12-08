package sumcheck

import (
	"fmt"
	"gkr-mimc/common"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMultiThreaded(t *testing.T) {
	bN := 8
	nChunks := 4 // nChunks < 2 ** bN
	prover := InitializeMultiThreadedProver(bN, nChunks)
	claim := prover.GetClaim(1)
	proof, _, _, _, _ := prover.Prove(1)
	verifier := Verifier{}
	valid, _, _, _, _ := verifier.Verify(claim, proof, 1, 1)
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
