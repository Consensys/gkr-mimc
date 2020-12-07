package sumcheck

import (
	"github.com/consensys/gurvy/bn256/fr"
)

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
