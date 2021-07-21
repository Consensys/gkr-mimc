package examples

import (
	"github.com/consensys/gkr-mimc/circuit"
	"github.com/consensys/gkr-mimc/hash"
)

// CreateMimcCircuit returns the GKR MIMC proving circuit
func CreateMimcCircuit() circuit.Circuit {
	nRounds := 91
	wiring := make([][]circuit.Wire, nRounds)

	for i := 0; i < nRounds-1; i++ {
		wiring[i] = []circuit.Wire{
			circuit.Wire{L: 1, R: 0, O: 0, Gate: circuit.NewCipherGate(hash.Arks[i])},
			circuit.Wire{L: 1, R: 0, O: 1, Gate: circuit.CopyGate{}},
		}
	}

	// And we don't copy the input in the last layer
	wiring[nRounds-1] = []circuit.Wire{
		circuit.Wire{L: 1, R: 0, O: 0, Gate: circuit.NewCipherGate(hash.Arks[nRounds-1])},
	}

	return circuit.NewCircuit(wiring)
}
