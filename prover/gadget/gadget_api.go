package gadget

import (
	"github.com/AlexandreBelling/gnark/frontend"
)

// Pass the update of a hasher to GKR
func (g *GkrGadget) UpdateHasher(
	cs frontend.API,
	state frontend.Variable,
	msg frontend.Variable,
) frontend.Variable {

	// Call the hint to get the hash. Since the circuit does not compute the full evaluation
	// of Mimc, we preprocess the inputs to let the circuit work
	output := cs.NewHint(g.HashHint, state, msg)

	// Since the circuit does not exactly computes the hash,
	// we are left to "finish the computation" by readding the state
	g.ioStore.Push(
		cs,
		[]frontend.Variable{cs.Add(msg, state), state},
		[]frontend.Variable{cs.Sub(output, msg, state)},
	)

	return output
}
