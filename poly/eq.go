package poly

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

// FoldedEqTable ought to start life as a sparse bookkeeping table
// depending on 2n variables and containing 2^n ones only
// to be folded n times according to the values in qPrime.
// The resulting table will no longer be sparse.
// Instead we directly compute the folded array of length 2^n
// containing the values of Eq(q1, ... , qn, *, ... , *)
// where qPrime = [q1 ... qn].
func FoldedEqTable(preallocated MultiLin, qPrime []fr.Element, multiplier ...fr.Element) (eq MultiLin) {
	n := len(qPrime)

	preallocated[0].SetOne()
	if len(multiplier) > 0 {
		preallocated[0] = multiplier[0]
	}

	for i, r := range qPrime {
		for j := 0; j < (1 << i); j++ {
			J := j << (n - i)
			JNext := J + 1<<(n-1-i)
			preallocated[JNext].Mul(&r, &preallocated[J])
			preallocated[J].Sub(&preallocated[J], &preallocated[JNext])
		}
	}

	return preallocated
}

// Computes only a chunk of the eqTable for a given chunkSize and chunkID
func ChunkOfEqTable(preallocatedEq []fr.Element, chunkID, chunkSize int, qPrime []fr.Element, multiplier ...fr.Element) {
	nChunks := (1 << len(qPrime)) / chunkSize
	logNChunks := common.Log2Ceil(nChunks)
	one := fr.One()
	var tmp fr.Element

	r := one

	if len(multiplier) > 0 {
		r = multiplier[0]
	}

	for k := 0; k < logNChunks; k++ {
		_rho := &qPrime[logNChunks-k-1]
		if chunkID>>k&1 == 1 { // If the k-th bit of i is 1
			r.Mul(&r, _rho)
		} else {
			tmp.Sub(&one, _rho)
			r.Mul(&r, &tmp)
		}
	}

	FoldedEqTable(
		preallocatedEq[chunkID*chunkSize:(chunkID+1)*chunkSize],
		qPrime[logNChunks:],
		r,
	)
}
