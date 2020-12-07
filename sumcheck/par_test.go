package sumcheck

import (
	"fmt"
	"gkr-mimc/common"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMultiThreaded(t *testing.T) {
	bN := 8
	nChunks := 4 // nChunks < 2 ** bN
	prover := InitializeProverForTests(bN)
	claim := prover.GetClaim()
	proof, _, _, _, _ := prover.ProveMultiThreaded(nChunks)
	verifier := Verifier{}
	valid, _, _, _, _ := verifier.Verify(claim, proof, 1, 1)
	assert.True(t, valid, "Verifier failed")
}

func benchmarkFullSumcheckMultiThreaded(b *testing.B, bN, nChunks int, profiled, traced bool) {
	b.ResetTimer()
	for _count := 0; _count < b.N; _count++ {
		prover := InitializeProverForTests(bN)
		common.ProfileTrace(b, profiled, traced,
			func() {
				prover.ProveMultiThreaded(nChunks)
			},
		)
	}
}

func BenchmarkSumcheckMultiThreaded(b *testing.B) {
	bNs := [1]int{20}
	nChunk := 8

	for _, bN := range bNs {
		b.Run(fmt.Sprintf("bN=%d", bN), func(b *testing.B) {
			benchmarkFullSumcheckMultiThreaded(b, bN, nChunk, false, true)
		})
	}
}
