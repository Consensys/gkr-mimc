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
	var arkBig big.Int
	for _, m := range stream {
		oldState := state
		for i := 0; i < hash.MimcRounds; i++ {
			hash.Arks[i].ToBigIntRegular(&arkBig)
			// keys := cs.Constant(hash.Arks[i])
			statemk := cs.LinearExpression(
				cs.Term(one, &arkBig),
				cs.Term(m, big.NewInt(1)),
				cs.Term(state, big.NewInt(1)),
			)
			// Raise to the power 7
			tmp := cs.Mul(statemk, statemk) // ^2
			tmp = cs.Mul(statemk, tmp)      // ^3
			tmp = cs.Mul(tmp, tmp)          // ^6
			state = cs.Mul(statemk, tmp)    // ^7
		}
		// Readd the oldState and the message as part of the Miyaguchi-Preenel construct
		state = cs.Add(state, oldState, m)
	}
	return state
}
