package hash

import (
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
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

	// compute permutation
	for i := 0; i < MimcRounds; i++ {
		block.Add(&block, state)
		block.Add(&block, &Arks[i])
		SBoxInplace(&block)
	}

	// state <- result of permutation
	state.Add(&block, state)

	/*
		It seems redundant to add the key at this point since we will use this
		block cipher to produce a Hash function via Miyaguchi-Preneel where
		the cipher text produced from the state and the block is used to update
		the state like so: state <- cipher + block + state. But we do it anyway.
		As does HarryR for instance.
	*/
}
