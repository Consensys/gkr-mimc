package circuit

import (
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

// Function that can be used to evalute a wire
// res a is a preallocated array containing the result in which we should write
type Evaluator func(res []fr.Element, in ...[]fr.Element)

// Variable describes a circuit variable
type Layer struct {
	// Variables indexes that are inputs to compute the current variable
	Inwards []int
	// Variables indexes that are fed by the current variable
	Outwards []int
	// Expresses how to build the variable
	Gate Gate
	// Optional method to help solving faster
	// Computes the solving and put it in chunk
	CustomEvaluator Evaluator
}

// // NewLayer construct a new layer from a list of wires
// func NewLayer(wires []Wire) Layer {
// 	return Layer{
// 		Wires:     wires,
// 		Gates:     Gates(wires),
// 		BGInputs:  BGInputs(wires),
// 		BGOutputs: BGOutputs(wires),
// 	}
// }

// // Evaluate returns the assignment of the next layer
// // It can be multi-threaded
// func (l *Layer) Evaluate(inputs [][]fr.Element, nCore int) [][]fr.Element {
// 	res := make([][]fr.Element, len(inputs))
// 	nIterations := len(inputs)

// 	f := l.defaultEvaluation
// 	if l.CustomEvaluator != nil {
// 		// Uses the custom function, when applicable
// 		f = l.CustomEvaluator
// 	}

// 	evaluateOnRange := func(start, stop int) {
// 		for k := start; k < stop; k++ {
// 			res[k] = f(inputs[k])
// 		}
// 	}

// 	common.Parallelize(nIterations, evaluateOnRange, nCore)
// 	return res
// }

// func (l *Layer) defaultEvaluation(inps []fr.Element) []fr.Element {
// 	GInputs := 1 << l.BGInputs
// 	GOutputs := 1 << l.BGOutputs
// 	N := len(inps) / GInputs
// 	subRes := make([]fr.Element, N*GOutputs)
// 	var tmp fr.Element
// 	for _, w := range l.Wires {
// 		// Precompute the indices
// 		wON := w.O * N
// 		wLN := w.L * N
// 		wRN := w.R * N
// 		for h := 0; h < N; h++ {
// 			// Runs the gate evaluator
// 			w.Gate.Eval(&tmp, &inps[wLN+h], &inps[wRN*N+h])
// 			subRes[wON+h].Add(&subRes[wON+h], &tmp)
// 		}
// 	}
// 	return subRes
// }

// // BGOutputs return the log-size of the input layer of the layer
// func BGOutputs(wires []Wire) int {
// 	res := 0
// 	for _, wire := range wires {
// 		if res < wire.O {
// 			res = wire.O
// 		}
// 	}
// 	return common.Log2Ceil(res + 1)
// }

// // BGInputs return the log-size of the input layer of the layer
// func BGInputs(wires []Wire) int {
// 	res := 0
// 	for _, wire := range wires {
// 		if res < wire.L {
// 			res = wire.L
// 		}
// 		if res < wire.R {
// 			res = wire.R
// 		}
// 	}
// 	return common.Log2Ceil(res + 1)
// }

// // Gates returns a deduplicated list of gates used by this layer
// func Gates(wires []Wire) []Gate {
// 	gates := make(map[string]Gate)
// 	res := []Gate{}
// 	for _, wire := range wires {
// 		if _, ok := gates[wire.Gate.ID()]; !ok {
// 			res = append(res, wire.Gate)
// 		}
// 	}
// 	return res
// }
