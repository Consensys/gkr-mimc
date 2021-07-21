package hash

import (
	"github.com/consensys/gkr-mimc/hash"

	"github.com/consensys/gnark/frontend"
)

// MimcHash returns the result of the hashing function
func MimcHash(cs *frontend.ConstraintSystem, stream ...frontend.Variable) frontend.Variable {
	state := cs.Constant(0)
	for _, m := range stream {
		oldState := state
		for i := 0; i < hash.MimcRounds; i++ {
			// keys := cs.Constant(hash.Arks[i])
			state = cs.Add(m, state, cs.Constant(hash.Arks[i]))
			// Raise to the power 7
			tmp := cs.Mul(state, state) // ^2
			tmp = cs.Mul(state, tmp)    // ^3
			tmp = cs.Mul(tmp, tmp)      // ^6
			state = cs.Mul(state, tmp)  // ^7
		}
		// Readd the oldState and the message as part of the Miyaguchi-Preenel construct
		state = cs.Add(state, oldState, m)
	}
	return state
}
