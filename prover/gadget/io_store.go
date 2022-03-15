package gadget

import (
	"fmt"

	"github.com/AlexandreBelling/gnark/frontend"
	"github.com/consensys/gkr-mimc/circuit"
	"github.com/consensys/gkr-mimc/common"
	"github.com/consensys/gkr-mimc/snark/polynomial"
)

const DEFAULT_IO_STORE_ALLOCATION_EPOCH int = 32

// Stores the inputs and is responsible for the reordering tasks
type IoStore struct {
	inputs            []polynomial.MultiLin // The variables as Gkr inputs
	inputsVarIds      [][]int               // The variable IDs as Gkr outputs
	inputsIsConstant  [][]bool              // True if the variable is a constant
	outputs           polynomial.MultiLin   // The variables as Gkr outputs
	outputsVarIds     []int                 // The ids of the variable as Gkr outputs
	outputsIsConstant []bool                // True if the variable is a constant
	allocEpoch        int
	index             int
	inputArity        int
	// Our implementation only support an arity of 1 for the outputs
}

// Creates a new ioStore for the given circuit
func NewIoStore(circuit *circuit.Circuit, allocEpoch int) IoStore {

	if allocEpoch == 0 {
		panic("cannot accept allocEpoch = 0")
	}

	return IoStore{
		inputs:     make([]polynomial.MultiLin, circuit.InputArity()),
		outputs:    polynomial.MultiLin{},
		allocEpoch: allocEpoch,
		inputArity: circuit.InputArity(),
	}
}

// Return the number of element allocated
func (io *IoStore) Index() int {
	return io.index
}

// Add an element in the ioStack
func (io *IoStore) Push(cs frontend.API, inputs []frontend.Variable, output frontend.Variable) {

	// Check that the dimension of the provided arrays is consistent with what was expected
	if len(inputs) != io.inputArity {
		panic(fmt.Sprintf("Expected inputs/outputs to have size %v but got %v",
			io.inputArity, len(inputs),
		))
	}

	// Enforces everything as a wire in place
	for i := range inputs {
		inputs[i] = cs.EnforceWire(inputs[i])
	}

	// And the output...
	output = cs.EnforceWire(output)

	// Performs an allocation if necessary
	io.allocateForOneMore()

	// Append the inputs
	for i := range inputs {
		wire := inputs[i]
		wireID, wireConstant := cs.WireId(wire)
		io.inputs[i] = append(io.inputs[i], wire)
		io.inputsVarIds[i] = append(io.inputsVarIds[i], wireID)
		io.inputsIsConstant[i] = append(io.inputsIsConstant[i], wireConstant)
	}

	// Append the output
	wire := output
	wireID, wireConstant := cs.WireId(wire)
	io.outputs = append(io.outputs, wire)
	io.outputsVarIds = append(io.outputsVarIds, wireID)
	io.outputsIsConstant = append(io.outputsIsConstant, wireConstant)

	io.index++
}

// Returns the io for the prover multiexp
// Done by concatenating the two into another array
func (io *IoStore) DumpForProverMultiExp() []frontend.Variable {

	// Allocate the result
	resSize := io.index * (io.inputArity + 1)
	res := make([]frontend.Variable, 0, resSize)

	// Sanity checks
	common.Assert(len(io.inputs[0]) == io.index, "mismatch between index and  %v / %v", len(io.inputs[0]), io.index)

	// Filling the vector
	for i := range io.inputs {
		res = append(res, io.inputs[i])
	}
	res = append(res, io.outputs)

	return res
}

// Returns the io for the prover multiexp
// Done by concatenating the two into another array
// The variables are returned in the form of a buffer of interfaces
// 4 empty entry are appended to the result : they are used by the hint to figure out which
// res = qPrime || inputs || outputs
func (io *IoStore) DumpForGkrProver(qPrimeArg []frontend.Variable) []frontend.Variable {

	// Allocate the result
	nInputs, nOutputs, bN := len(io.inputs[0])*io.inputArity, len(io.outputs), len(qPrimeArg)
	resSize := nInputs + nOutputs + bN
	res := make([]frontend.Variable, 0, resSize)

	// Sanity checks: as we can assume to be in the Mimc case
	common.Assert(len(io.inputs[0]) == io.index, "The input arity is inconsistent %v / %v", len(io.inputs), io.index)
	common.Assert(1<<bN == io.index, "bN is inconsistent with the index")

	// Filling the vector
	res = append(res, qPrimeArg)
	for i := range io.inputs {
		res = append(res, io.inputs[i])
	}
	res = append(res, io.outputs)

	return res
}

// Returns the gkr inputs in the correct order to be processed by the verifier
func (io *IoStore) InputsForVerifier() []polynomial.MultiLin {
	return io.inputs
}

// Returns the gkr outputs in the correct order to be processed by the verifier
func (io *IoStore) OutputsForVerifier() polynomial.MultiLin {
	return io.outputs
}

// Returns all the varIds in a single vec (no deduplication)
func (io *IoStore) VarIds() []int {
	res := make([]int, 0, io.index*(io.inputArity+1))
	for i := range io.inputsVarIds {
		res = append(res, io.inputsVarIds[i]...)
	}
	res = append(res, io.outputsVarIds...)
	return res
}

// Returns all the `isConstant` concatenated in a single vec
func (io *IoStore) VarAreConstant() []bool {
	res := make([]bool, 0, io.index*(io.inputArity+1))
	for i := range io.inputsIsConstant {
		res = append(res, io.inputsIsConstant[i]...)
	}
	res = append(res, io.outputsIsConstant...)
	return res
}

// Allocates for one more hash entry
func (io *IoStore) allocateForOneMore() {

	if io.index >= io.allocEpoch {

		// Double the size
		incInputs := io.index
		for i := range io.inputs {
			io.inputs[i] = IncreaseCapVariable(io.inputs[i], incInputs)
			io.inputsVarIds[i] = IncreaseCapInts(io.inputsVarIds[i], incInputs)
			io.inputsIsConstant[i] = IncreaseCapBools(io.inputsIsConstant[i], incInputs)
		}

		incOutputs := io.index
		io.outputs = IncreaseCapVariable(io.outputs, incOutputs)
		io.outputsVarIds = IncreaseCapInts(io.outputsVarIds, incOutputs)
		io.outputsIsConstant = IncreaseCapBools(io.outputsIsConstant, incOutputs)

		io.allocEpoch *= 2
	}
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
