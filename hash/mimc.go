package hash

import (
	"github.com/consensys/gurvy/bn256/fr"
)

// MimcRounds is the number of rounds for the Mimc function
const MimcRounds int = 91

// MimcHash returns the hash of a slice of field element
func MimcHash(input []fr.Element) fr.Element {
	// The state is initialized to zero
	var state fr.Element
	for _, x := range input {
		MimcUpdateInplace(&state, x)
	}
	return state
}

// MimcUpdateInplace performs a state update using the Mimc permutation
func MimcUpdateInplace(state *fr.Element, block fr.Element) {
	oldState := *state
	MimcPermutationInPlace(state, block)
	// TODO: readds the oldstate addition, when gnark moves to Miyaguchi-Preenel
	state.Add(state, &oldState)
	state.Add(state, &block)
}

// MimcPermutationInPlace applies the mimc permutation in place
func MimcPermutationInPlace(state *fr.Element, block fr.Element) {
	for i := 0; i < MimcRounds; i++ {
		keys := Arks[i]
		keys.Add(&keys, &block)
		state.Add(state, &keys)
		SBoxInplace(state)
	}
}
