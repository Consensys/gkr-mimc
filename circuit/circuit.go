package circuit

import (
	"gkr-mimc/polynomial"

	"github.com/consensys/gurvy/bn256/fr"
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
func (a *Assignment) LayerAsBKTWithCopy(layer int) []polynomial.BookKeepingTable {
	res := make([]polynomial.BookKeepingTable, len(a.Values[layer]))
	// Deep-copies the values of the assignment
	for i, tab := range a.Values[layer] {
		res[i].Table = make([]fr.Element, len(tab))
		copy(res[i].Table, tab)
	}
	return res
}

// LayerAsBKTNoCopy creates a deep-copy of a given layer of the assignment
func (a *Assignment) LayerAsBKTNoCopy(layer int) []polynomial.BookKeepingTable {
	res := make([]polynomial.BookKeepingTable, len(a.Values[layer]))
	// Copies the headers of the slices
	for i, tab := range a.Values[layer] {
		res[i] = polynomial.NewBookKeepingTable(tab)
	}
	return res
}
