package sumcheck2

import (
	"fmt"
	"testing"

	"github.com/consensys/gkr-mimc/circuit"
	"github.com/consensys/gkr-mimc/circuit/gates"
	"github.com/consensys/gkr-mimc/common"
	"github.com/consensys/gkr-mimc/polynomial"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

func initializeSumcheckInstance(bN int) (L, R polynomial.BookKeepingTable, qPrime []fr.Element, gate circuit.Gate) {

	q := make([]fr.Element, bN)
	for i := range q {
		q[i].SetUint64(2)
	}

	L = make([]fr.Element, 1<<bN)
	R = make([]fr.Element, 1<<bN)

	for i := range L {
		L[i].SetUint64(uint64(i))
		R[i].SetUint64(uint64(i))
	}

	return polynomial.NewBookKeepingTable(L),
		polynomial.NewBookKeepingTable(R),
		q, gates.NewCipherGate(fr.NewElement(1632134))
}

func BenchmarkSumcheck(b *testing.B) {
	bn := 22
	b.Run(fmt.Sprintf("sumcheck-bn-%v", bn), func(b *testing.B) {
		common.ProfileTrace(b, false, false, func() {
			for c_ := 0; c_ < b.N; c_++ {
				b.StopTimer()
				L, R, qPrime, gate := initializeSumcheckInstance(bn)
				b.StartTimer()
				_, _, _ = Prove(L, R, qPrime, gate)
			}
			b.StopTimer()
		})
	})
}

// func BenchmarkEval(b *testing.B) {
// 	bN := 20
// 	b.Run(fmt.Sprintf("partial-poly-bn-%v", bN), func(b *testing.B) {
// 		i := initializeSumcheckInstance(bN)
// 		b.ResetTimer()
// 		for c_ := 0; c_ < b.N; c_++ {
// 			_ = i.getPartialPoly()
// 		}
// 		b.StopTimer()
// 	})
// }

// func BenchmarkFolding(b *testing.B) {
// 	bN := 22
// 	r := fr.NewElement(45463346)
// 	b.Run(fmt.Sprintf("folding-bn-%v", bN), func(b *testing.B) {
// 		for c_ := 0; c_ < b.N; c_++ {
// 			b.StopTimer()
// 			i := initializeSumcheckInstance(bN)
// 			b.StartTimer()
// 			i.fold(r)
// 		}
// 	})
// }
