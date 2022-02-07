package polynomial

import (
	"fmt"
	"math"
	"runtime"
	"sync"

	"github.com/consensys/gkr-mimc/common"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

// BookKeepingTable tracks the values of a (dense i.e. not sparse) multilinear polynomial
type BookKeepingTable []fr.Element

func (bkt BookKeepingTable) String() string {
	return fmt.Sprintf("table = %v", common.FrSliceToString(bkt))
}

// NewBookKeepingTable returns a new instance of bookkeeping table
func NewBookKeepingTable(table []fr.Element) BookKeepingTable {
	return table
}

// InterleavedChunk returns a single chunk from an interleaved splitting
func (bkt BookKeepingTable) InterleavedChunk(on, nChunk int) BookKeepingTable {
	chunkSize := len(bkt) / nChunk
	table := make([]fr.Element, chunkSize)
	for i := 0; i < chunkSize; i++ {
		table[i] = bkt[on+i*nChunk]
	}
	return NewBookKeepingTable(table)
}

// Fold folds the table on its first coordinate using the given value r
func (bkt *BookKeepingTable) Fold(r fr.Element) {

	bkt_ := *bkt
	mid := bkt.middleIndex()
	bottom, top := bkt_[:mid], bkt_[mid:]

	// If have mid / nCpu lower, than this threshold, then each goroutine works for less than 1 ms
	PARALLELIZATION_THRESHOLD := float64(1 << 14)
	numCpus := int(math.Ceil(float64(mid) / PARALLELIZATION_THRESHOLD)) // Therefore we should not use more than this number of thread
	numCpus = common.Min(numCpus, runtime.NumCPU())

	common.Parallelize(mid, func(start, stop int) {
		for i := start; i < stop; i++ {
			// updating bookkeeping table
			// table[i] <- table[i] + r (table[i + mid] - table[i])
			top[i].Sub(&top[i], &bottom[i])
			top[i].Mul(&top[i], &r)
			bottom[i].Add(&bottom[i], &top[i])
		}
	}, numCpus)

	*bkt = bkt_[:mid]
}

// FunctionEvals evaluates implicitly over the first variable in bkt
// E.g. if one has to interpolate, say, x |--> (x + cst)^7 with x in the bkt,
// We return the value P(r, 0, b), and delta = P(r, 1, b) - P(r, 0, b) in an array
// [P(r, 0, b), delta]
func (bkt BookKeepingTable) FunctionEvals() []fr.Element {
	mid := bkt.middleIndex()
	fEvals := make([]fr.Element, mid)
	bottom, top := bkt[:mid], bkt[mid:]

	for i := range bottom {
		fEvals[i].Sub(&top[i], &bottom[i])
	}

	return fEvals
}

func (bkt BookKeepingTable) middleIndex() int {
	return len(bkt) / 2
}

// DeepCopy creates a deep copy of a book-keeping table.
// Both ultilinear interpolation and sumcheck require folding an underlying
// array, but folding changes the array. To do both one requires a deep copy
// of the book-keeping table.
func (bkt BookKeepingTable) DeepCopy() BookKeepingTable {
	tableDeepCopy := make([]fr.Element, len(bkt))
	copy(tableDeepCopy, bkt)
	return NewBookKeepingTable(tableDeepCopy)
}

// Evaluate takes a dense book-keeping table, deep copies it, folds it along the
// variables on which the table depends by substituting the corresponding coordinate
// from relevantCoordinates. After folding, bkCopy is reduced to a one item slice
// containing the evaluation of the original bkt at relevantCoordinates. This is returned.
func (bkt BookKeepingTable) Evaluate(coordinates []fr.Element) fr.Element {
	bkCopy := bkt.DeepCopy()
	for _, r := range coordinates {
		bkCopy.Fold(r)
	}

	return bkCopy[0]
}

// EvaluateLeftAndRight produces two evaluations of a book-keeping table V:
// V(q,l) and V(q,r). Folding is first done along the first done for q, then two
// copies are generated to handle the further copies.
// Variable order: [q', q, hl, hr, h']
func (bkt BookKeepingTable) EvaluateLeftAndRight(hPrime, hL, hR []fr.Element) (fr.Element, fr.Element) {

	bkCopyLeft := bkt.DeepCopy()
	bkCopyRight := bkt.DeepCopy()

	// Fix a bug where hPrime, hL and hR are all subSlices of the same table
	coordinatesLeft := append([]fr.Element{}, hL...)
	coordinatesLeft = append(coordinatesLeft, hPrime...)
	coordinatesRight := append([]fr.Element{}, hR...)
	coordinatesRight = append(coordinatesRight, hPrime...)

	leftEval, rightEval := bkCopyLeft.Evaluate(coordinatesLeft),
		bkCopyRight.Evaluate(coordinatesRight)
	return leftEval, rightEval
}

// LinearCombinationOfBookKeepingTables is an alternative to
// LinearCombinationOfBookKeepingTable
func LinearCombinationOfBookKeepingTables(
	prefoldedBKT0, prefoldedBKT1 BookKeepingTable,
	a0, a1 fr.Element,
) BookKeepingTable {

	// CAREFUL: indices to be confirmed!
	// In BOTH CASES ought to be: bN + uint(i)
	// Variables: order & size:
	// q',	q,	r,	l,	h'
	// bN,	bG,	bG,	bG,	bN
	for i := range prefoldedBKT1 {
		prefoldedBKT0[i].Mul(&prefoldedBKT0[i], &a0)
		prefoldedBKT1[i].Mul(&prefoldedBKT1[i], &a1)
		prefoldedBKT1[i].Add(&prefoldedBKT1[i], &prefoldedBKT0[i])
	}

	return prefoldedBKT1
}

// Add two bookKeepingTable
func (bkt BookKeepingTable) Add(left, right BookKeepingTable) {
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

// Sub two bookKeepingTable
func (bkt BookKeepingTable) Sub(left, right BookKeepingTable, nCore int) {
	size := len(left)
	chunks := common.IntoChunkRanges(nCore, size)
	semaphore := common.NewSemaphore(nCore)
	var wg sync.WaitGroup
	wg.Add(len(chunks))

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
	for _, chunk := range chunks {
		semaphore.Acquire()
		go func(chunk common.ChunkRange) {
			for i := chunk.Begin; i < chunk.End; i++ {
				bkt[i].Sub(&left[i], &right[i])
			}
			semaphore.Release()
			wg.Done()
		}(chunk)
	}

	wg.Wait()
}

// Mul a bookkeeping table by a constant
func (bkt BookKeepingTable) Mul(lambda fr.Element, x BookKeepingTable, nCore int) {
	size := len(x)
	chunks := common.IntoChunkRanges(nCore, size)
	semaphore := common.NewSemaphore(nCore)
	var wg sync.WaitGroup
	wg.Add(len(chunks))

	// Reallocate the table if necessary
	if cap(bkt) < size {
		bkt = make([]fr.Element, size)
	}

	// Resize the destination table
	bkt = bkt[:size]
	// Then performs the addition
	for _, chunk := range chunks {
		semaphore.Acquire()
		go func(chunk common.ChunkRange) {
			for i := chunk.Begin; i < chunk.End; i++ {
				bkt[i].Mul(&x[i], &lambda)
			}
			semaphore.Release()
			wg.Done()
		}(chunk)
	}
	wg.Wait()
}
