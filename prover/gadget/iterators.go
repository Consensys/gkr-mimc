package gadget

import "github.com/consensys/gnark-crypto/ecc/bn254/fr"

// Chains the running of multiple iterators
type ChainedSlicesIterator struct {
	slices     [][]fr.Element
	index      int
	indexInner int
}

// Construct a new empty chained iterator
func NewChainedSlicesIterator() *ChainedSlicesIterator {
	return &ChainedSlicesIterator{
		slices:     make([][]fr.Element, 0),
		index:      0,
		indexInner: 0,
	}
}

// Set the capacity to the min between the current and the passed capacity
// Panic if the slice already has been set already
func (c *ChainedSlicesIterator) SetCapacity(cap int) {
	// Sanity check
	if len(c.slices) > 0 {
		panic("Attempted to set capacity but the iterator already has items")
	}

	c.slices = make([][]fr.Element, 0, cap)
}

// WasLast indicates if the sliceIterator is finished. IE: if it's true
// it will panic if we call Next() once more
func (c *ChainedSlicesIterator) Next() (val fr.Element, finished bool) {
	if c.isFinished() {
		// Does not do anything, indicate the iterator was already finished
		return fr.Element{}, true
	}
	val = c.slices[c.index][c.indexInner]
	c.incIndices()
	return val, false
}

// update the index and indexInner so they point to the next location
// Returns true iff the iteration is finished
func (c *ChainedSlicesIterator) incIndices() {
	// No need to check a second time that the iterator was not consumed. We do it in Next already.
	// If the inner slices is not iterated over completely, only increment the inner index
	if c.indexInner+1 < len(c.slices[c.index]) {
		c.indexInner++
	}

	// Otherwise, point at the first entry of the next slice
	c.indexInner = 0
	c.index++
}

// Returns true iff the iterator contains no more items
func (c *ChainedSlicesIterator) isFinished() bool {
	return c.index >= len(c.slices)
}

// Chain the iterator to the chainedIterator
func (c *ChainedSlicesIterator) Chain(slices ...[]fr.Element) *ChainedSlicesIterator {
	c.slices = append(c.slices, slices...)
	return c
}
