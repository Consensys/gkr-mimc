package poly

import (
	"fmt"

	"github.com/consensys/gkr-mimc/common"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

// MultiLin tracks the values of a (dense i.e. not sparse) multilinear polynomial
type MultiLin []fr.Element

func (bkt MultiLin) String() string {
	return fmt.Sprintf("%v", common.FrSliceToString(bkt))
}

// Fold folds the table on its first coordinate using the given value r
func (bkt *MultiLin) Fold(r fr.Element) {
	mid := len(*bkt) / 2
	bkt.FoldChunk(r, 0, mid)
	*bkt = (*bkt)[:mid]
}

// Folds one part of the table
func (bkt *MultiLin) FoldChunk(r fr.Element, start, stop int) {
	mid := len(*bkt) / 2
	bottom, top := (*bkt)[:mid], (*bkt)[mid:]
	for i := start; i < stop; i++ {
		// updating bookkeeping table
		// table[i] <- table[i] + r (table[i + mid] - table[i])
		top[i].Sub(&top[i], &bottom[i])
		top[i].Mul(&top[i], &r)
		bottom[i].Add(&bottom[i], &top[i])
	}
}

// DeepCopy creates a deep copy of a book-keeping table.
// Both ultilinear interpolation and sumcheck require folding an underlying
// array, but folding changes the array. To do both one requires a deep copy
// of the book-keeping table.
func (bkt MultiLin) DeepCopy() MultiLin {
	tableDeepCopy := make([]fr.Element, len(bkt))
	copy(tableDeepCopy, bkt)
	return tableDeepCopy
}

// DeepCopy creates a deep copy of a multi-linear table.
func (bkt MultiLin) DeepCopyLarge() MultiLin {
	tableDeepCopy := MakeLarge(len(bkt))
	copy(tableDeepCopy, bkt)
	return tableDeepCopy
}

// Evaluate takes a dense book-keeping table, deep copies it, folds it along the
// variables on which the table depends by substituting the corresponding coordinate
// from relevantCoordinates. After folding, bkCopy is reduced to a one item slice
// containing the evaluation of the original bkt at relevantCoordinates. This is returned.
func (bkt MultiLin) Evaluate(coordinates []fr.Element) fr.Element {
	bkCopy := bkt.DeepCopy()
	for _, r := range coordinates {
		bkCopy.Fold(r)
	}

	return bkCopy[0]
}

// Add two bookKeepingTable
func (bkt MultiLin) Add(left, right MultiLin) {
	size := len(left)
	// Check that left and right have the same size
	if len(right) != size {
		panic("Left and right do not have the right size")
	}
	// Reallocate the table if necessary
	if cap(bkt) < size {
		bkt = make([]fr.Element, size)
	}
	// Resize the destination table
	bkt = bkt[:size]
	// Then performs the addition
	for i := 0; i < size; i++ {
		bkt[i].Add(&left[i], &right[i])
	}
}

// RandomFrArray returns a random array
func RandMultiLin(size int) MultiLin {
	return common.RandomFrArray(size)
}
