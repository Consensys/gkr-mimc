package circuit

import (
	"github.com/consensys/gkr-mimc/common"
	"github.com/consensys/gkr-mimc/poly"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

// Circuit contains all the statical informations necessary to
// describe a GKR circuit.
type Circuit struct {
	Layers []Layer
}

// Assignment gathers all the values representing the steps of
// computations being proved by GKR
type Assignment struct {
	Values [][][]fr.Element
}

// NewCircuit construct a new circuit object
func NewCircuit(
	wiring [][]Wire,
) Circuit {
	layers := make([]Layer, len(wiring))
	for i := range layers {
		layers[i] = NewLayer(wiring[i])
	}
	return Circuit{
		Layers: layers,
	}
}

// Assign returns a complete assignment from a vector of inputs
func (c *Circuit) Assign(inputs [][]fr.Element, nCore int) Assignment {
	assignment := make([][][]fr.Element, len(c.Layers)+1)
	// The first layer of assignment is equal to the inputs
	assignment[0] = inputs
	// We use the transition funcs to create the next layers
	// one after the other
	for i, layer := range c.Layers {
		assignment[i+1] = layer.Evaluate(assignment[i], nCore)
	}
	return Assignment{Values: assignment}
}

// LayerAsBKTWithCopy creates a deep-copy of a given layer of the assignment
func (a *Assignment) LayerAsBKTWithCopy(layer, nCore int) []poly.MultiLin {
	res := make([]poly.MultiLin, len(a.Values[layer]))

	subCopy := func(start, stop int) {
		for i := start; i < stop; i++ {
			tab := a.Values[layer][i]
			res[i] = make([]fr.Element, len(tab))
			copy(res[i], tab)
		}
	}

	common.Parallelize(len(res), subCopy, nCore)
	return res
}

// LayerAsBKTNoCopy creates a deep-copy of a given layer of the assignment
func (a *Assignment) LayerAsBKTNoCopy(layer int) []poly.MultiLin {
	res := make([]poly.MultiLin, len(a.Values[layer]))
	// Copies the headers of the slices
	for i, tab := range a.Values[layer] {
		res[i] = tab
	}
	return res
}

// Returns the output size of the circuit
func (c *Circuit) OutputArity() int {
	return 1 << c.Layers[len(c.Layers)-1].BGOutputs
}

// Returns the input arity of the circuit
func (c *Circuit) InputArity() int {
	return 1 << c.Layers[len(c.Layers)-1].BGInputs
}
