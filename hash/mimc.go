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
// Using Miyaguchi-Preenel
func MimcUpdateInplace(state *fr.Element, block fr.Element) {
	oldState := *state
	MimcPermutationInPlace(state, block)
	state.Add(state, &oldState)
	state.Add(state, &block)
}

// MimcPermutationInPlace applies the mimc permutation in place
// In the Miyaguchi-Preenel construct, the state is used as the key of a cipher function
// and the message to hash is set as the plaintext of the cipher
func MimcPermutationInPlace(state *fr.Element, block fr.Element) {
	for i := 0; i < MimcRounds; i++ {
		block.Add(&block, state)
		block.Add(&block, &Arks[i])
		SBoxInplace(&block)
	}
	// Re-add the state (key) to the block and put the result in the state
	// to update the state
	state.Add(state, &block)
}
