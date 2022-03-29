package circuit

import (
	"github.com/consensys/gkr-mimc/poly"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

// Assignment for a GKR circuit
type Assignment []poly.MultiLin

// Assign computes the full assignment
func (c Circuit) Assign(inps ...poly.MultiLin) (a Assignment) {

	a = make(Assignment, len(c))

	// Assigns the provided input layers
	for i := 0; i < len(inps); i++ {
		a[i] = inps[i].DeepCopyLarge()
	}

	for i := len(inps); i < len(a); i++ {

		inp := make([][]fr.Element, len(c[i].In))
		for j := range inp {
			inp[j] = a[c[i].In[j]]
		}

		a[i] = c[i].Evaluate(inp...)
	}

	return a
}

// InputsOfLayer returns the input layers of the layer l
func (a Assignment) InputsOfLayer(c Circuit, l int) []poly.MultiLin {
	positions := c[l].In
	res := make([]poly.MultiLin, len(positions))

	for i := range res {

		pos := positions[i]
		// We want to know if current layer `l` is the first output of layer `pos`*
		// Indeed, `Out` is guaranteed to be sorted in ascending order.
		// It matters, because the result will be mutated by the sumcheck prover
		// and we may need to use a layer's output more than once
		isFirst := c[pos].Out[0] == l

		if isFirst {
			// Then no need to deep-copy
			res[i] = a[pos]
		} else {
			res[i] = a[pos].DeepCopyLarge()
		}
	}

	return res
}

// Dump assignment into large pool
func (a Assignment) Dump() {
	for _, p := range a {
		poly.DumpLarge(p)
	}
}
