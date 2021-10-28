package gkr_gadget

import (
	"github.com/consensys/gkr-mimc/circuit"
	"github.com/consensys/gkr-mimc/snark/gkr"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/frontend"
)

// Helper for performing hashes using GKR
type GkrGadget struct {
	// Pointers to variables that must have been allocated somewhere else
	inputs          []*frontend.Variable
	outputs         []frontend.Variable
	assignedInputs  []fr.Element
	assignedOutputs []fr.Element
	DefineIndex     int
	AssignIndex     int
	Capacity        int
	Circuit         circuit.Circuit
	Proof           gkr.Proof
}

// Allocate the Gadget for bN. The circuit will expect exactly the right bN
func AllocateGkrGadget(bN int, circuit circuit.Circuit) GkrGadget {
	// Maximum amount of hashes that can be performed by the circuit
	capacity := 1 << bN
	return GkrGadget{
		inputs:   make([]*frontend.Variable, 0, 2*capacity),
		outputs:  make([]frontend.Variable, 0, capacity),
		Capacity: capacity,
		Circuit:  circuit,
		// TODO: Merge the gate framwork inside the SNARK
		// Proof:    gkr.AllocateProof(bN, circuit),
	}
}

// Pass the update of a hasher to GKR
func (g *GkrGadget) UpdateHasher(
	cs *frontend.ConstraintSystem,
	state frontend.Variable,
	msg frontend.Variable,
) frontend.Variable {
	panic("Boom")
}

// Pad and close GKR, run the proof
func (g *GkrGadget) Close() {
	// PAD every input in the define
	// Define the proof
	// Run GKR verifier in the define
}
