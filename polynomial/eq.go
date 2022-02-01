package polynomial

import (
	"github.com/consensys/gkr-mimc/common"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

// EvalEq computes Eq(q1', ... , qn', h1', ... , hn') = Π_1^n Eq(qi', hi')
// where Eq(x,y) = xy + (1-x)(1-y) = 1 - x - y + xy + xy interpolates
//      _________________
//      |       |       |
//      |   0   |   1   |
//      |_______|_______|
//  y   |       |       |
//      |   1   |   0   |
//      |_______|_______|
//
//              x
func EvalEq(qPrime, nextQPrime []fr.Element) fr.Element {
	var res, nxt, one, sum fr.Element
	one.SetOne()
	res.SetOne()
	for i := 0; i < len(qPrime); i++ {
		nxt.Mul(&qPrime[i], &nextQPrime[i]) // nxt <- qi' * hi'
		nxt.Add(&nxt, &nxt)                 // nxt <- 2 * qi' * hi'
		nxt.Add(&nxt, &one)                 // nxt <- 1 + 2 * qi' * hi'
		sum.Add(&qPrime[i], &nextQPrime[i]) // sum <- qi' + hi'
		nxt.Sub(&nxt, &sum)                 // nxt <- 1 + 2 * qi' * hi' - qi' - hi'
		res.Mul(&res, &nxt)                 // res <- res * nxt
	}
	return res
}

// GetFoldedEqTable ought to start life as a sparse bookkeepingtable
// depending on 2n variables and containing 2^n ones only
// to be folded n times according to the values in qPrime.
// The resulting table will no longer be sparse.
// Instead we directly compute the folded array of length 2^n
// containing the values of Eq(q1, ... , qn, *, ... , *)
// where qPrime = [q1 ... qn].
func GetFoldedEqTable(qPrime []fr.Element) (eq BookKeepingTable) {
	return foldedEqTableWithMultiplier(qPrime, fr.One())
}

func foldedEqTableWithMultiplier(qPrime []fr.Element, multiplier fr.Element) (eq BookKeepingTable) {
	n := len(qPrime)
	foldedEqTable := make([]fr.Element, 1<<n)
	foldedEqTable[0] = multiplier

	for i, r := range qPrime {
		for j := 0; j < (1 << i); j++ {
			J := j << (n - i)
			JNext := J + 1<<(n-1-i)
			foldedEqTable[JNext].Mul(&r, &foldedEqTable[J])
			foldedEqTable[J].Sub(&foldedEqTable[J], &foldedEqTable[JNext])
		}
	}

	return NewBookKeepingTable(foldedEqTable)
}

// GetChunkedEqTable returns a prefolded eq table, in chunked form
func GetChunkedEqTable(qPrime []fr.Element, nChunks, nCore int) []BookKeepingTable {
	logNChunks := common.Log2Ceil(nChunks)
	res := make([]BookKeepingTable, nChunks)

	common.Parallelize(
		nChunks,
		func(start, stop int) {
			// Useful preallocations
			var tmp fr.Element
			one := fr.One()
			for noChunk := start; noChunk < stop; noChunk++ {
				// Compute r
				r := one
				for k := 0; k < logNChunks; k++ {
					_rho := &qPrime[len(qPrime)-k-1]
					if noChunk>>k&1 == 1 { // If the k-th bit of i is 1
						r.Mul(&r, _rho)
					} else {
						tmp.Sub(&one, _rho)
						r.Mul(&r, &tmp)
					}
				}

				res[noChunk] = foldedEqTableWithMultiplier(qPrime[:len(qPrime)-logNChunks], r)
			}
		},
		nCore,
	)

	return res
}
