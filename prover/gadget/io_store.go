package gadget

import (
	"fmt"

	"github.com/AlexandreBelling/gnark/frontend"
	"github.com/consensys/gkr-mimc/circuit"
	"github.com/consensys/gkr-mimc/common"
)

const DEFAULT_IO_STORE_ALLOCATION_EPOCH int = 32

// Stores the inputs and is responsible for the reordering tasks
type IoStore struct {
	inputs            []frontend.Variable // The variables as Gkr inputs
	inputsVarIds      []int               // The variable IDs as Gkr outputs
	inputsIsConstant  []bool              // True if the variable is a constant
	outputs           []frontend.Variable // The variables as Gkr outputs
	outputsVarIds     []int               // The ids of the variable as Gkr outputs
	outputsIsConstant []bool              // True if the variable is a constant
	allocEpoch        int
	index             int
	inputArity        int
	outputArity       int
}

// Creates a new ioStore for the given circuit
func NewIoStore(circuit *circuit.Circuit, allocEpoch int) IoStore {

	if allocEpoch == 0 {
		panic("cannot accept allocEpoch = 0")
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

		incInputs := io.inputArity * (io.allocEpoch + io.index)
		io.inputs = IncreaseCapVariable(io.inputs, incInputs)
		io.inputsVarIds = IncreaseCapInts(io.inputsVarIds, incInputs)
		io.inputsIsConstant = IncreaseCapBools(io.inputsIsConstant, incInputs)

		incOutputs := io.outputArity * (io.allocEpoch + io.index)
		io.outputs = IncreaseCapVariable(io.outputs, incOutputs)
		io.outputsVarIds = IncreaseCapInts(io.outputsVarIds, incOutputs)
		io.outputsIsConstant = IncreaseCapBools(io.outputsIsConstant, incOutputs)
	}
}

// Return the number of element allocated
func (io *IoStore) Index() int {
	return io.index
}

func (io *IoStore) PushVarIds(inputs, outputs []int) {
	// Check that the dimension of the provided arrays is consistent with what was expected
	if len(inputs) != io.inputArity || len(outputs) != io.outputArity {
		panic(fmt.Sprintf("Expected inputs/outputs to have size %v/%v but got %v/%v",
			io.inputArity, io.outputArity, len(inputs), len(outputs),
		))
	}

	io.inputsVarIds = append(io.inputsVarIds, inputs...)
	io.outputsVarIds = append(io.outputsVarIds, outputs...)
}

// Add an element in the ioStack
func (io *IoStore) Push(cs frontend.API, inputs, outputs []frontend.Variable) {

	// Check that the dimension of the provided arrays is consistent with what was expected
	if len(inputs) != io.inputArity || len(outputs) != io.outputArity {
		panic(fmt.Sprintf("Expected inputs/outputs to have size %v/%v but got %v/%v",
			io.inputArity, io.outputArity, len(inputs), len(outputs),
		))
	}

	// Enforces everything as a wire in place
	for i := range inputs {
		inputs[i] = cs.EnforceWire(inputs[i])
	}

	// And the outputs...
	for i := range outputs {
		outputs[i] = cs.EnforceWire(outputs[i])
	}

	// Performs an allocation if necessary
	io.allocateForOneMore()

	// Append the inputs
	for i := range inputs {
		wire := inputs[i]
		wireID, wireConstant := cs.WireId(wire)
		io.inputs = append(io.inputs, wire)
		io.inputsVarIds = append(io.inputsVarIds, wireID)
		io.inputsIsConstant = append(io.inputsIsConstant, wireConstant)
	}

	// Append the outputs
	for i := range outputs {
		wire := outputs[i]
		wireID, wireConstant := cs.WireId(wire)
		io.outputs = append(io.outputs, wire)
		io.outputsVarIds = append(io.outputsVarIds, wireID)
		io.outputsIsConstant = append(io.outputsIsConstant, wireConstant)
	}

	io.index++
}

// Returns the io for the prover multiexp
// Done by concatenating the two into another array
func (io *IoStore) DumpForProverMultiExp() []frontend.Variable {
	return append(io.inputs, io.outputs...)
}

// Returns the io for the prover multiexp
// Done by concatenating the two into another array
// The variables are returned in the form of a buffer of interfaces
// 4 empty entry are appended to the result : they are used by the hint to figure out which
func (io *IoStore) DumpForGkrProver(chunkSize int, qPrimeArg, qArg []frontend.Variable) []frontend.Variable {

	// If the chunk size if too big, mutates to 1 << len(qPrimeArg)
	chunkSize = common.Min(chunkSize, 1<<len(qPrimeArg))

	nChunks := io.Index() / chunkSize
	nInputs, nOutputs, bN, bG := len(io.inputs), len(io.outputs), len(qPrimeArg), len(qArg)
	resSize := nInputs + nOutputs + bN + bG
	res := make([]frontend.Variable, resSize)

	// Allocate subslices for each part of the dump
	drain := res[:]
	dumpedInputs, drain := drain[:nInputs], drain[nInputs:]
	dumpedOutputs, drain := drain[:nOutputs], drain[nOutputs:]
	qPrime, drain := drain[:bN], drain[bN:]
	q, drain := drain[:bG], drain[bG:]

	// Sanity checks: as we can assume to be in the Mimc case
	common.Assert(len(q) == 0, "length of q must be 0")
	common.Assert(len(qArg) == 0, "Length of qArg must be 0")
	common.Assert(len(drain) == 0, "The drain should be empty")
	common.Assert(
		len(io.inputs) == io.index*io.inputArity,
		"The input arity is inconsistent %v / %v", len(io.inputs), io.index*io.inputArity)
	common.Assert(len(io.outputs) == io.index*io.outputArity,
		"The output arity is inconsistent %v / %v", len(io.outputs), io.index*io.outputArity)
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
			nI := chunkSize * nChunks
			for subI := 0; subI < io.inputArity; subI++ {
				dumpIdx := msb + lsb*nChunks + subI*nI
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
			nO := chunkSize * nChunks
			for subO := 0; subO < io.outputArity; subO++ {
				dumpIdx := msb + lsb*nChunks + subO*nO
				ioIdx := subO + lsb*io.outputArity + msb*chunkSizeXoutputArity
				dumpedOutputs[dumpIdx] = io.outputs[ioIdx]
			}
		}
	}

	return dumpedOutputs
}

// Increase the capacity of a slice of frontend variable
func IncreaseCapVariable(arr []frontend.Variable, by int) []frontend.Variable {
	res := make([]frontend.Variable, 0, len(arr)+by)
	res = append(res, arr...)
	return res
}

// Increase the capacity of a slice of integers
func IncreaseCapInts(arr []int, by int) []int {
	res := make([]int, 0, len(arr)+by)
	res = append(res, arr...)
	return res
}

// Increase the capacity of a slice of boolean
func IncreaseCapBools(arr []bool, by int) []bool {
	res := make([]bool, 0, len(arr)+by)
	res = append(res, arr...)
	return res
}
