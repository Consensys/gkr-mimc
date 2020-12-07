package hash

import (
	"gkr-mimc/hash"
	"math/big"

	"github.com/consensys/gnark/frontend"
)

// MimcHash returns the result of the hashing function
func MimcHash(cs *frontend.ConstraintSystem, stream ...frontend.Variable) frontend.Variable {
	state := cs.Constant(0)
	one := cs.Constant(1)
	var keys big.Int
	for _, m := range stream {
		oldState := state
		for i := 0; i < hash.MimcRounds; i++ {
			hash.Arks[i].ToBigInt(&keys)
			// state = cs.Add(keys, m, state)
			tmp := cs.LinearExpression(
				cs.Term(one, &keys),
				cs.Term(m, big.NewInt(1)),
				cs.Term(state, big.NewInt(1)),
			)
			// Applies the SBox
			state = cs.Mul(tmp, tmp)     // ^2
			state = cs.Mul(state, tmp)   // ^3
			state = cs.Mul(state, state) // ^6
			state = cs.Mul(state, tmp)   // ^7
		}
		state = cs.Add(state, oldState, m)
	}
	return state
}
