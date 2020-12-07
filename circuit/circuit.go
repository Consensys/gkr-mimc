package circuit

import (
	"gkr-mimc/sumcheck"

	"github.com/consensys/gurvy/bn256/fr"
)

// Assignment gathers all the values representing the steps of
// computations being proved by GKR
type Assignment struct {
	values [][]fr.Element
}

// TransitionFunc takes a layer as input and returns the values
// for the next layer. It should be adaptative to the number of
// subcircuits
// f(V_level_i) -> V_level_i+1
type TransitionFunc func([]fr.Element) []fr.Element

// TableGenerator takes an array of challenges (q and not q') and returns a
// (pre-folded) sumcheck.BookKeepingTable.
// f(q) -> APrefoldedTable (It takes q and NOT qPrime)
type TableGenerator func([]fr.Element) sumcheck.BookKeepingTable

// Circuit contains all the statical informations necessary to
// describe a GKR circuit.
type Circuit struct {
	// bGs is the size of the sub-circuit for each layer
	bGs []int
	// The gates to be used in the circuits. The order must be consistent with
	// staticTableGens
	gates [][]sumcheck.Gate
	// The transitions functions are used to create an assignment array
	// from a vector of inputs.
	transitionFuncs []TransitionFunc
	// The table generators are used to represent the circuit. The generated
	// tables must be in the same order `gates`.
	// The static tables are the table of the kind "add, mul, copy, cipher...".
	// /!\ Note that Eq is not included.
	staticTableGens [][]TableGenerator
}

// LayerAsBKTWithCopy creates a deep-copy of a given layer of the assignment
func (a *Assignment) LayerAsBKTWithCopy(layer int) sumcheck.BookKeepingTable {
	// Deep-copies the values of the assignment
	return sumcheck.NewBookKeepingTable(append([]fr.Element{}, a.values[layer]...))
}

// LayerAsBKTNoCopy creates a deep-copy of a given layer of the assignment
func (a *Assignment) LayerAsBKTNoCopy(layer int) sumcheck.BookKeepingTable {
	// Deep-copies the values of the assignment
	return sumcheck.NewBookKeepingTable(a.values[layer])
}

// EvalLayer ( layer ) computes V_layer(qPrimeCurr, qCurr) by repeated folding
// recall V_layer is the polynomial taking the values of assignment at layer on the hypercube.
func (a *Assignment) EvalLayer(layer int, qPrime, q []fr.Element) fr.Element {
	// compute V_{level}(qPrimeCurr, qCurr) and set claimCurr accordingly
	// LHSV <-> left hand side V (w.r.t. sumcheck problem (*))
	bkt := a.LayerAsBKTNoCopy(layer)
	evalAt := append(qPrime, q...)
	return bkt.Evaluate(evalAt)
}

// getClaim( layer ) computes V_layer(qPrimeCurr, qCurr) by repeated folding
// recall V_layer is the polynomial taking the values of assignment at layer on the hypercube.
func (a *Assignment) getClaims(layer int, qPrime, qL, qR []fr.Element) (fr.Element, fr.Element) {
	// compute V_{level}(qPrimeCurr, qCurr) and set claimCurr accordingly
	// LHSV <-> left hand side V (w.r.t. sumcheck problem (*))
	bkTable := a.LayerAsBKTNoCopy(layer) // Evaluate performs the copy
	return bkTable.EvaluateLeftAndRight(qPrime, qL, qR)
}

// Gates returns the gates at `layer`
func (c *Circuit) Gates(layer int) []sumcheck.Gate {
	return c.gates[layer]
}

// NewCircuit construct a new circuit object
func NewCircuit(
	bGs []int,
	gates [][]sumcheck.Gate,
	transitionFuncs []TransitionFunc,
	staticTableGens [][]TableGenerator,
) Circuit {

	if len(transitionFuncs) != len(staticTableGens) {
		panic("Could not create a circuit, combinators, transitionFuncs and staticTableGens")
	}

	return Circuit{
		bGs:             bGs,
		gates:           gates,
		transitionFuncs: transitionFuncs,
		staticTableGens: staticTableGens,
	}
}

// GetStaticTableGens returns the TableGenerator for the static tables
// of a given layer of the circuit
func (c *Circuit) GetStaticTableGens(layer int) []TableGenerator {
	return c.staticTableGens[layer]
}

// GenerateAssignment returns a complete assignment from a vector of inputs
func (c *Circuit) GenerateAssignment(inputs []fr.Element) Assignment {
	assignment := make([][]fr.Element, len(c.transitionFuncs)+1)
	// The first layer of assignment is equal to the inputs
	assignment[0] = inputs
	// We use the transition funcs to create the next layers
	// one after the other
	for i, f := range c.transitionFuncs {
		assignment[i+1] = f(assignment[i])
	}
	return Assignment{values: assignment}
}
