package circuit

import (
	"github.com/consensys/gkr-mimc/circuit/gates"
	"github.com/consensys/gkr-mimc/hash"
)

// Mimc returns the GKR MIMC proving circuit
func Mimc() Circuit {
	nRounds := 91

	c := make(Circuit, nRounds+3)

	// Contains the `block` of the permutations
	c[0] = Layer{In: []int{}}
	// Contains the initial state of the permutation
	c[1] = Layer{In: []int{}}
	// Multi-instance layer of the key : added explicitly
	c[2] = Layer{In: []int{0}, Gate: gates.IdentityGate{}}

	for i := 0; i < nRounds; i++ {
		inp := i + 2
		if i == 0 {
			// Points to 1 : not the multi-instance
			inp = 1
		}

		c[i+3] = Layer{In: []int{2, inp}, Gate: gates.NewCipherGate(hash.Arks[i])}
	}

	if err := BuildCircuit(c); err != nil {
		panic(err)
	}

	return c
}
