package hash

import (
	"gkr-mimc/hash"

	"github.com/consensys/gnark/frontend"
)

// MimcHash returns the result of the hashing function
func MimcHash(cs *frontend.ConstraintSystem, stream ...frontend.Variable) frontend.Variable {
	state := cs.Constant(0)
	for _, m := range stream {
		oldState := state
		for i := 0; i < hash.MimcRounds; i++ {
			keys := cs.Constant(hash.Arks[i])
			state = cs.Add(keys, m, state)
			// Applies the SBox
			tmp := state
			state = cs.Mul(state, state) // ^2
			state = cs.Mul(state, tmp)   // ^3
			state = cs.Mul(state, state) // ^6
			state = cs.Mul(state, tmp)   // ^7
		}
		state = cs.Add(state, oldState, m)
	}
	return state
}
