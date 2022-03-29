package circuit

import (
	"fmt"

	"github.com/consensys/gkr-mimc/common"
	"github.com/consensys/gkr-mimc/poly"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

type Circuit []Layer

// Variable describes a circuit variable
type Layer struct {
	// Variables indexes that are inputs to compute the current variable
	// Empty, means this an input layer
	In []int
	// Variables indexes that are fed by the current variable
	// Empty means this is an output layer
	Out []int
	// Expresses how to build the variable
	Gate Gate
}

// BuildCircuit
// - Computes the Out layers
// - Ensures there is no input used more than once : multi-instances must be explicitly provided as intermediary layers
func BuildCircuit(c Circuit) error {
	// Computes the output layers
	for l := range c {
		for _, pos := range c[l].In {
			c[pos].Out = append(c[pos].Out, l)
		}
	}

	// Counts the number of multi-instances
	for l := range c {
		if len(c[l].In) == 0 && len(c[l].Out) > 1 {
			return fmt.Errorf("layer %v is an input layer but has %v outputs", l, len(c[l].Out))
		}
	}

	return nil
}

// Evaluate returns the assignment of the next layer
// It can be multi-threaded
func (l *Layer) Evaluate(inputs ...[]fr.Element) []fr.Element {
	nbIterations := len(inputs[0])
	res := poly.MakeLarge(nbIterations)

	common.Parallelize(nbIterations,
		func(start, stop int) {

			inps := make([][]fr.Element, len(inputs))
			for i := 0; i < len(inputs); i++ {
				inps[i] = inputs[i][start:stop]
			}

			l.Gate.EvalBatch(res[start:stop], inps...)
		},
	)
	return res
}

// IsInputLayer returns true/false if this is an input layer
// There are multiple ways of checking a layer is an input or output
// All of them are checked. This helps as a sanity checks :
// it will panic if any of the checks contradict the others.
func (c Circuit) IsInputLayer(layer int) bool {
	hasNoInputs := len(c[layer].In) == 0
	hasNogates := c[layer].Gate == nil

	if hasNoInputs != hasNogates {
		panic(fmt.Sprintf("layer %v has no inputs? : %v but also has no gate? : %v", layer, hasNoInputs, hasNogates))
	}

	return hasNoInputs
}
