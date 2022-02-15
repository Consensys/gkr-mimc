package examples

import (
	"github.com/consensys/gkr-mimc/circuit"
	"github.com/consensys/gkr-mimc/circuit/gates"
	"github.com/consensys/gkr-mimc/hash"
)

// Mimc returns the GKR MIMC proving circuit
func Mimc() circuit.Circuit {
	nRounds := 91

	c := make(circuit.Circuit, nRounds+3)

	// Contains the `block` of the permutations
	c[0] = circuit.Layer{In: []int{}}
	// Contains the initial state of the permutation
	c[1] = circuit.Layer{In: []int{}}
	// Multi-instance layer of the key : added explicitly
	c[2] = circuit.Layer{In: []int{0}, Gate: gates.IdentityGate{}}

	for i := 0; i < nRounds; i++ {
		inp := i + 2
		if i == 0 {
			// Points to 1 : not the multi-instance
			inp = 1
		}

		c[i+3] = circuit.Layer{In: []int{2, inp}, Gate: gates.NewCipherGate(hash.Arks[i])}
	}

	if err := circuit.BuildCircuit(c); err != nil {
		panic(err)
	}

	return c
}
