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
// In the Miyaguchi-Preenel construct, the state is used as the key of a cipher function
// and the message to hash is set as the plaintext of the cipher
func MimcUpdateInplace(state *fr.Element, block fr.Element) {
	newState := MimcBlockCipher(block, *state)
	state.Add(state, &newState)
	state.Add(state, &block)
}

// MimcKeyedPermutation iterates the Mimc rounds functions over x with key k
func MimcKeyedPermutation(x fr.Element, key fr.Element) fr.Element {
	res := x
	for i := 0; i < MimcRounds; i++ {
		res.Add(&res, &key)
		res.Add(&res, &Arks[i])
		SBoxInplace(&res)
	}
	return res
}

// MimcBlockCipher the mimc permutation in place
// In the papier; E_k(x) = Perm_k(x) + k
func MimcBlockCipher(msg fr.Element, key fr.Element) fr.Element {
	res := MimcKeyedPermutation(msg, key)
	// Re-add the state (key) to the block and put the result in the state
	// to update the state
	res.Add(&res, &key)
	return res
}
