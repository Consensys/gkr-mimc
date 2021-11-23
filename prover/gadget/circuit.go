package gadget

import (
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/notinternal/backend/bn254/cs"
	"github.com/consensys/gnark/notinternal/backend/bn254/groth16"
	"github.com/consensys/gnark/notinternal/backend/bn254/witness"
)

// Interface to be implemented by any circuit willing to use Gkr
type CircuitUsingGkr interface {
	Define(curveID ecc.ID, cs frontend.API, gadget *GkrGadget) error
}

// Generic wrapper circuit in which, we can plug any circuit using
// Gkr. The wrapper holds all the logic for the proving etc...
type Circuit struct {
	Gadget       GkrGadget
	InnerCircuit CircuitUsingGkr
}

// Wraps the given circuit into a `Circuit` object
func WrapCircuitUsingGkr(c CircuitUsingGkr, opts ...GkrOption) Circuit {
	w := Circuit{
		InnerCircuit: c,
		Gadget:       *NewGkrGadget(),
	}
	// Applies the options
	for _, opt := range opts {
		opt(&w)
	}
	return w
}

// Implements `gnark`s circuit interface
func (c *Circuit) Define(curveID ecc.ID, cs frontend.API) error {
	if err := c.InnerCircuit.Define(curveID, cs, &c.Gadget); err != nil {
		return err
	}
	c.Gadget.Close(cs)
	return nil
}

// Assigns for the subcircuit
func (c *Circuit) Assign() {
	c.Gadget.InitialRandomness.Assign(0)
}

// The first error it returns is the "solver error". So we expect it.
// The second one is for unexected errors
func (c *Circuit) partialSolve(compiled frontend.CompiledConstraintSystem, opts ...func(opt *backend.ProverOption) error) (Solution, error, error) {
	witness := witness.Witness{}
	err := witness.FromFullAssignment(c)

	if err != nil {
		return Solution{}, nil, err
	}

	opts = append(opts, backend.WithHints(c.Gadget.InitialRandomnessHint, c.Gadget.HashHint, c.Gadget.GkrProverHint))
	proverOption, err := backend.NewProverOption(opts...)

	if err != nil {
		return Solution{}, nil, err
	}

	r1csHard := compiled.(*cs.R1CS)
	wires, aSol, bSol, cSol, _ := groth16.Solve(r1csHard, witness, proverOption)

	return Solution{A: aSol, B: bSol, C: cSol, Wires: wires}, err, nil
}

// Returns a solution to the circuit
func (c *Circuit) Solve(compiled frontend.CompiledConstraintSystem, opt ...func(opt *backend.ProverOption) error) (Solution, error) {
	solution, solverError, err := c.partialSolve(compiled, opt...)
	if err != nil {
		// Got an unexpected error
		return Solution{}, err
	}

	if !solution.Fix() {
		// The solver had a non fixable error, we return it
		return Solution{}, solverError
	}

	return solution, err
}

// Options for the `Circuit` constructor
type GkrOption func(c *Circuit)

// Mutates the chunkSize of the circuit
func WithChunkSize(chunkSize int) GkrOption {
	return func(c *Circuit) {
		c.Gadget.chunkSize = chunkSize
	}
}

// Mutates the chunkSize of the circuit
func WithNCore(n int) GkrOption {
	return func(c *Circuit) {
		c.Gadget.gkrNCore = n
	}
}
