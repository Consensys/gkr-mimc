package gadget

import (
	"fmt"

	"github.com/consensys/gkr-mimc/circuit"
	"github.com/consensys/gkr-mimc/common"
	"github.com/consensys/gnark/frontend"
)

const DEFAULT_IO_STORE_ALLOCATION_EPOCH int = 32

// Stores the inputs and is responsible for the reordering tasks
type IoStore struct {
	inputs      []frontend.Variable
	outputs     []frontend.Variable
	allocEpoch  int
	index       int
	inputArity  int
	outputArity int
}

// Creates a new ioStore for the given circuit
func NewIoStore(circuit *circuit.Circuit, allocEpoch int) IoStore {

	if allocEpoch == 0 {
		panic(fmt.Sprintf("Cannot accept allocEpoch = 0"))
	}

	return IoStore{
		inputs:      []frontend.Variable{},
		outputs:     []frontend.Variable{},
		allocEpoch:  allocEpoch,
		inputArity:  circuit.InputArity(),
		outputArity: circuit.OutputArity(),
	}
}

// Allocates for one more hash entry
func (io *IoStore) allocateForOneMore() {
	if io.index%io.allocEpoch == 0 {
		// Extends the inputs slice capacity
		inputs := make([]frontend.Variable, 0, io.inputArity*(io.allocEpoch+io.index))
		copy(inputs, io.inputs)
		io.inputs = inputs
		// Extends the outputs slice capacity
		outputs := make([]frontend.Variable, 0, io.outputArity*(io.allocEpoch+io.index))
		copy(outputs, io.outputs)
		io.outputs = outputs
	}
}

// Return the number of element allocated
func (io *IoStore) Index() int {
	return io.index
}

// Add an element in the ioStack
func (io *IoStore) Push(inputs, outputs []frontend.Variable) {

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

	io.index++
}

// Returns the io for the prover multiexp
// Done by concatenating the two into another array
// The element are also converted to interfaces, in order to please the hint
func (io *IoStore) DumpForProverMultiExp() []interface{} {
	nInputs := len(io.inputs)
	res := make([]interface{}, nInputs+len(io.outputs))

	for i := range io.inputs {
		res[i] = io.inputs[i]
	}

	for i := range io.outputs {
		res[i+nInputs] = io.outputs[i]
	}

	return res
}

// Returns the io for the prover multiexp
// Done by concatenating the two into another array
// The variables are returned in the form of a buffer of interfaces
// 4 empty entry are appended to the result : they are used by the hint to figure out which
func (io *IoStore) DumpForGkrProver(chunkSize int, qPrimeArg, qArg []frontend.Variable) []interface{} {

	nChunks := io.Index() / chunkSize
	nInputs, nOutputs, bN, bG := len(io.inputs), len(io.outputs), len(qPrimeArg), len(qArg)
	resSize := nInputs + nOutputs + bN + bG + 4
	res := make([]interface{}, resSize)

	// Allocate subslices for each part of the dump
	drain := res[4:]
	dumpedInputs, drain := drain[:nInputs], drain[nInputs:]
	dumpedOutputs, drain := drain[:nOutputs], drain[nOutputs:]
	qPrime, drain := drain[:bN], drain[bN:]
	q, drain := drain[:bG], drain[bG:]

	// Sanity checks: as we can assume to be in the Mimc case
	common.Assert(len(q) == 0, "length of q must be 0")
	common.Assert(len(qArg) == 0, "Length of qArg must be 0")
	common.Assert(len(drain) == 0, "The drain should be empty")
	common.Assert(len(io.inputs) == io.index*io.inputArity, "The input arity is inconsistent")
	common.Assert(len(io.outputs) == io.index*io.outputArity, "The output arity is inconsistent")
	common.Assert(1<<bN == io.index, "bN is inconsistent with the index")

	// Bare copy for qPrime and qArg.
	// We can't use copy here because it's `[]interface{} <- []fr.Element`
	for i := range qPrime {
		qPrime[i] = qPrimeArg[i]
	}

	for i := range q {
		q[i] = qArg[i]
	}

	// Then assigns the inputs outputs by reordering
	for msb := 0; msb < nChunks; msb++ {
		for lsb := 0; lsb < chunkSize; lsb++ {
			chunkSizeXinputArity := chunkSize * io.inputArity
			chunkSizeXoutputArity := chunkSize * io.outputArity

			// Reorder the inputs
			for subI := 0; subI < io.inputArity; subI++ {
				dumpIdx := lsb + subI*chunkSize + msb*chunkSizeXinputArity
				storeIdx := subI + lsb*io.inputArity + msb*chunkSizeXinputArity
				dumpedInputs[dumpIdx] = io.inputs[storeIdx]
			}

			// Reorder the outputs
			for subO := 0; subO < io.outputArity; subO++ {
				dumpIdx := lsb + subO*chunkSize + msb*chunkSizeXoutputArity
				storeIdx := subO + lsb*io.outputArity + msb*chunkSizeXoutputArity
				dumpedOutputs[dumpIdx] = io.outputs[storeIdx]
			}
		}
	}

	return res
}

// Returns the gkr inputs in the correct order to be processed by the verifier
func (io *IoStore) InputsForVerifier(chunkSize int) []frontend.Variable {
	nChunks := io.Index() / chunkSize
	nInputs := len(io.inputs)
	resSize := nInputs
	dumpedInputs := make([]frontend.Variable, resSize)

	// Sanity checks: as we can assume to be in the Mimc case
	common.Assert(len(io.inputs) == io.index*io.inputArity, "The input arity is inconsistent")

	// Then assigns the inputs outputs by reordering
	for msb := 0; msb < nChunks; msb++ {
		for lsb := 0; lsb < chunkSize; lsb++ {
			chunkSizeXinputArity := chunkSize * io.inputArity
			for subI := 0; subI < io.inputArity; subI++ {
				dumpIdx := lsb + subI*chunkSize + msb*chunkSizeXinputArity
				ioIdx := subI + lsb*io.inputArity + msb*chunkSizeXinputArity
				dumpedInputs[dumpIdx] = io.inputs[ioIdx]
			}
		}
	}

	return dumpedInputs

}

// Returns the gkr outputs in the correct order to be processed by the verifier
func (io *IoStore) OutputsForVerifier(chunkSize int) []frontend.Variable {
	nChunks := io.Index() / chunkSize
	nOutputs := len(io.outputs)
	resSize := nOutputs
	dumpedOutputs := make([]frontend.Variable, resSize)

	// Sanity checks: as we can assume to be in the Mimc case
	common.Assert(len(io.outputs) == io.index*io.outputArity, "The output arity is inconsistent")

	// Then assigns the inputs outputs by reordering
	for msb := 0; msb < nChunks; msb++ {
		for lsb := 0; lsb < chunkSize; lsb++ {
			chunkSizeXoutputArity := chunkSize * io.outputArity
			for subO := 0; subO < io.outputArity; subO++ {
				dumpIdx := lsb + subO*chunkSize + msb*chunkSizeXoutputArity
				ioIdx := subO + lsb*io.outputArity + msb*chunkSizeXoutputArity
				dumpedOutputs[dumpIdx] = io.outputs[ioIdx]
			}
		}
	}

	return dumpedOutputs
}
