package gadget

import "github.com/consensys/gnark/frontend"

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
	l := cs.EnforceWire(cs.Add(msg, state))
	r := cs.EnforceWire(state)
	o := cs.EnforceWire(cs.Sub(output, msg, state))

	g.ioStore.PushVarIds(
		[]int{l.WireId(), r.WireId()},
		[]int{o.WireId()},
	)

	g.ioStore.Push(
		[]frontend.Variable{l, r},
		[]frontend.Variable{o},
	)

	return output
}
