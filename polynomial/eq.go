package polynomial

import "github.com/consensys/gurvy/bn256/fr"

// GetFoldedEqTable ought to start life as a sparse bookkeepingtable
// depending on 2n variables and containing 2^n ones only
// to be folded n times according to the values in qPrime.
// The resulting table will no longer be sparse.
// Instead we directly compute the folded array of length 2^n
// containing the values of Eq(q1, ... , qn, *, ... , *)
// where qPrime = [q1 ... qn].
func GetFoldedEqTable(qPrime []fr.Element) []fr.Element {

	n := len(qPrime)
	foldedEqTable := make([]fr.Element, 1<<n)
	foldedEqTable[0].SetOne()

	for i, r := range qPrime {
		for j := 0; j < (1 << i); j++ {
			J := j << (n - i)
			JNext := J + 1<<(n-1-i)
			foldedEqTable[JNext].Mul(&r, &foldedEqTable[J])
			foldedEqTable[J].Sub(&foldedEqTable[J], &foldedEqTable[JNext])
		}
	}

	return foldedEqTable
}

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

// PrefoldedEqTable computes prefolded Eq book-keeping table
func PrefoldedEqTable(qPrime []fr.Element) (eq BookKeepingTable) {
	n := len(qPrime)
	foldedEqTable := make([]fr.Element, 1<<n)
	foldedEqTable[0].SetOne()

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
