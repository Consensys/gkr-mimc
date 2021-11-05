package gkr_gadget

import (
	"fmt"

	"github.com/consensys/gkr-mimc/circuit"
	"github.com/consensys/gnark/frontend"
)

const DEFAULT_IO_STORE_ALLOCATION_EPOCH int = 32

// Stores the inputs and is responsible for the reordering tasks
type ioStore struct {
	inputs      []frontend.Variable
	outputs     []frontend.Variable
	allocEpoch  int
	topIndex    int
	inputArity  int
	outputArity int
}

// Creates a new ioStore for the given circuit
func (io *ioStore) newIoStore(circuit *circuit.Circuit, allocEpoch int) ioStore {

	if allocEpoch == 0 {
		panic(fmt.Sprintf("Cannot accept allocEpoch = 0"))
	}

	return ioStore{
		inputs:      []frontend.Variable{},
		outputs:     []frontend.Variable{},
		allocEpoch:  allocEpoch,
		inputArity:  circuit.InputArity(),
		outputArity: circuit.OutputArity(),
	}
}

// Allocates for one more hash entry
func (io *ioStore) allocateForOneMore() {
	if io.topIndex%io.allocEpoch == 0 {
		// Extends the inputs slice capacity
		inputs := make([]frontend.Variable, 0, io.inputArity*(io.allocEpoch+io.topIndex))
		copy(inputs, io.inputs)
		io.inputs = inputs
		// Extends the outputs slice capacity
		outputs := make([]frontend.Variable, 0, io.outputArity*(io.allocEpoch+io.topIndex))
		copy(outputs, io.outputs)
		io.outputs = outputs
	}
}

// Return the number of element allocated
func (io *ioStore) Index() int {
	return io.topIndex
}

// Add an element in the ioStack
func (io *ioStore) Push(inputs, outputs []frontend.Variable) {

	// Check that the dimension of the provided arrays is consistent with what was expected
	if len(inputs) != io.inputArity || len(outputs) != io.outputArity {
		panic(fmt.Sprintf("Expected inputs/outputs to have size %v/%v but got %v/%v",
			io.inputArity, io.outputArity, len(inputs), len(outputs),
		))
	}

	// Performs an allocation
	io.allocateForOneMore()

	// If necessary
	io.inputs = append(io.inputs, inputs...)
	io.outputs = append(io.outputs, outputs...)

	io.topIndex++
}

// Returns the io for the prover multiexp
// Done by concatenating the two into another array
func (io *ioStore) DumpForProverMultiExp() []frontend.Variable {
	res := make([]frontend.Variable, 0)
	res = append(res, io.inputs...)
	res = append(res, io.outputs...)
	return res
}

// Returns the io for the prover multiexp
// Done by concatenating the two into another array
func (io *ioStore) DumpForGkrProver() []frontend.Variable {
	panic("Boom")
}

// Returns the gkr inputs in the correct order to be processed by the verifier
func (io *ioStore) InputsForVerifier() []frontend.Variable {
	panic("Boom")
}

// Returns the gkr outputs in the correct order to be processed by the verifier
func (io *ioStore) OutputsForVerifier() []frontend.Variable {
	panic("Boom")
}
