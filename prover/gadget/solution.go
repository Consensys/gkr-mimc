package gadget

import (
	"fmt"

	"github.com/AlexandreBelling/gnark/backend"
	"github.com/AlexandreBelling/gnark/frontend"
	"github.com/AlexandreBelling/gnark/notinternal/backend/bn254/cs"
	"github.com/AlexandreBelling/gnark/notinternal/backend/bn254/groth16"
	"github.com/AlexandreBelling/gnark/notinternal/backend/bn254/witness"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

type Solution struct {
	Wires, A, B, C []fr.Element
}

// Returns a solution to the circuit
func (c *Circuit) Solve(compiled R1CS, opt ...func(opt *backend.ProverOption) error) (Solution, error) {

	if compiled.provingKey == nil {
		return Solution{}, fmt.Errorf("Solving was called prior to running the setup.\n" +
			"Run either DummySetup(&r1cs) or Setup(&r1cs) prior to calling Solve.\n")
	}

	// Re-inject the R1CS into the circuit
	c.Gadget.r1cs = &compiled

	solution, solverError, err := c.partialSolve(&compiled.r1cs, opt...)
	if err != nil {
		// Got an unexpected error
		return Solution{}, err
	}

	if !solution.fixSolution() {
		// The solver had a non fixable error, we return it
		return Solution{}, solverError
	}

	return solution, err
}

// Fixes the partial solution delivered by the solver
func (s *Solution) fixSolution() bool {
	if !s.isFixable() {
		return false
	}

	nConstraint := len(s.A)
	// Fixes the solution with the right initial randomnes
	s.A[nConstraint-1] = s.C[nConstraint-1]
	s.Wires[1] = s.C[nConstraint-1]

	return true
}

// Returns true if the solution is "in partial form"
// Last constraint should be `0 x 1 = !0`. It's useful to
// check if the solver failed before the last constraint or before.
func (s *Solution) isFixable() bool {
	nConstraint := len(s.A)
	return s.A[nConstraint-1] == fr.NewElement(0) &&
		s.B[nConstraint-1] == fr.One() &&
		s.C[nConstraint-1] != fr.NewElement(0) &&
		s.Wires[1] == fr.NewElement(0)
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
