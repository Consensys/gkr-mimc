package circuit

import (
	"github.com/consensys/gkr-mimc/poly"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

// Assigment for a GKR circuit
type Assignment []poly.MultiLin

// Assign computes the full assignment
func (c Circuit) Assign(inps ...[]fr.Element) (a Assignment) {

	a = make(Assignment, len(c))

	// Assigns the provided input layers
	for i := 0; i < len(inps); i++ {
		a[i] = poly.MultiLin(inps[i]).DeepCopy()
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

// InputLayersOf returns the input layers of the layer l
func (a Assignment) InputsOfLayer(c Circuit, l int) []poly.MultiLin {
	positions := c[l].In
	res := make([]poly.MultiLin, len(positions))

	for i := range res {
		if positions[i] == l-1 {
			// Then no need to deep-copy
			res[i] = a[positions[i]]
		} else {
			res[i] = a[positions[i]].DeepCopyLarge()
		}
	}

	return res
}
