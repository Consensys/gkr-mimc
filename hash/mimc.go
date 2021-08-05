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

	// in case changing the block itself is undesirable
	tmp := block

	// compute permutation
	for i := 0; i < MimcRounds; i++ {
		tmp.Add(&tmp, state)
		tmp.Add(&tmp, &Arks[i])
		SBoxInplace(&tmp)
	}

	// state <- result of permutation
	state.Set(&tmp)

	// The block cipher described in "Efficient Encryption and Cryptographic Hashing with
	// Minimal Multiplicative Complexity" is different in two respects:
	//	- they add the key to tmp at the end,
	//	- their first round constant is 0.
	// if we wanted to do the final key addition we would have to insert `tmp.Add(&tmp, state)`
	// after the for loop and before `state.Set(&tmp)`.
	// It seems redundant to add the key since we will use this block cipher to produce a Hash
	// function using Miyaguchi-Preneel where the cipher text produced from the state and the
	// block is used to update the state like so: state <- cipher + block + state.
}
