package common

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
