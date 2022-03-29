package poly

import (
	"fmt"

	"github.com/consensys/gkr-mimc/common"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

// MultiLin tracks the values of a (dense i.e. not sparse) multilinear polynomial
type MultiLin []fr.Element

func (m MultiLin) String() string {
	return fmt.Sprintf("%v", common.FrSliceToString(m))
}

// Fold folds the table on its first coordinate using the given value r
func (m *MultiLin) Fold(r fr.Element) {
	mid := len(*m) / 2
	m.FoldChunk(r, 0, mid)
	*m = (*m)[:mid]
}

// FoldChunk folds one part of the table
func (m *MultiLin) FoldChunk(r fr.Element, start, stop int) {
	mid := len(*m) / 2
	bottom, top := (*m)[:mid], (*m)[mid:]
	for i := start; i < stop; i++ {
		// updating bookkeeping table
		// table[i] <- table[i] + r (table[i + mid] - table[i])
		top[i].Sub(&top[i], &bottom[i])
		top[i].Mul(&top[i], &r)
		bottom[i].Add(&bottom[i], &top[i])
	}
}

// DeepCopy creates a deep copy of a bookkeeping table.
// Both multilinear interpolation and sumcheck require folding an underlying
// array, but folding changes the array. To do both one requires a deep copy
// of the bookkeeping table.
func (m MultiLin) DeepCopy() MultiLin {
	tableDeepCopy := make([]fr.Element, len(m))
	copy(tableDeepCopy, m)
	return tableDeepCopy
}

// DeepCopyLarge creates a deep copy of a multilinear table.
func (m MultiLin) DeepCopyLarge() MultiLin {
	tableDeepCopy := MakeLarge(len(m))
	copy(tableDeepCopy, m)
	return tableDeepCopy
}

// Evaluate takes a dense bookkeeping table, deep copies it, folds it along the
// variables on which the table depends by substituting the corresponding coordinate
// from relevantCoordinates. After folding, bkCopy is reduced to a one item slice
// containing the evaluation of the original bkt at relevantCoordinates. This is returned.
func (m MultiLin) Evaluate(coordinates []fr.Element) fr.Element {
	bkCopy := m.DeepCopy()
	for _, r := range coordinates {
		bkCopy.Fold(r)
	}

	return bkCopy[0]
}
