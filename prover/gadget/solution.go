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

// Dump the solution vector : usefull for debugging
func (s Solution) Dump() {
	for i := range s.A {
		fmt.Printf("n = %v a = %v, b = %v, c = %v \n", i, s.A[i].String(), s.B[i].String(), s.C[i].String())
	}
}

// Returns a solution to the circuit
func (c *Circuit) Solve(compiled R1CS, opt ...func(opt *backend.ProverOption) error) (Solution, error) {

	if compiled.provingKey == nil {
		return Solution{}, fmt.Errorf("solving was called prior to running the setup" +
			"\n run either DummySetup(&r1cs) or Setup(&r1cs) prior to calling Solve")
	}

	// Re-inject the R1CS into the circuit
	c.Gadget.r1cs = &compiled

	solution, solverError, err := c.partialSolve(&compiled.r1cs, opt...)
	if err != nil {
		// Got an unexpected error
		return Solution{}, err
	}

	if err = solution.fixSolution(); err != nil {
		// The solver had a non fixable error, we return it
		return Solution{}, fmt.Errorf("%v \n %v", solverError, err)
	}

	return solution, err
}

// Fixes the partial solution delivered by the solver
func (s *Solution) fixSolution() error {
	nConstraint := len(s.A)
	errString := ""

	if s.A[nConstraint-1] != fr.One() {
		errString += fmt.Sprintf("a[nConstraint] should =1 but got %v \n", s.A[nConstraint-1].String())
	}

	if s.B[nConstraint-1] != fr.NewElement(0) {
		errString += fmt.Sprintf("b[nConstraint] should =0 but got %v \n", s.B[nConstraint-1].String())
	}

	if s.C[nConstraint-1] == fr.NewElement(0) {
		errString += fmt.Sprintf("c[nConstraint] should != 0 but got %v \n", s.C[nConstraint-1].String())
	}

	if s.Wires[1] != fr.NewElement(0) {
		errString += fmt.Sprintf("w[1] should be 0 but got %v \n", s.Wires[1].String())
	}

	if len(errString) > 0 {
		return fmt.Errorf(errString)
	}

	// Fixes the solution with the right initial randomnes
	// Which contained in CN
	s.B[nConstraint-1] = s.C[nConstraint-1]
	s.Wires[1] = s.C[nConstraint-1]

	return nil
}

// The first error it returns is the "solver error". So we expect it.
// The second one is for unexected errors
func (c *Circuit) partialSolve(compiled frontend.CompiledConstraintSystem, opts ...func(opt *backend.ProverOption) error) (Solution, error, error) {
	witness := witness.Witness{}

	err := witness.FromFullAssignment(c)

	if err != nil {
		return Solution{}, nil, err
	}

	opts = append(opts, backend.WithHints(c.Gadget.InitialRandomnessHint(), c.Gadget.HashHint(), c.Gadget.GkrProverHint()))
	proverOption, err := backend.NewProverOption(opts...)

	if err != nil {
		return Solution{}, nil, err
	}

	r1csHard := compiled.(*cs.R1CS)
	wires, aSol, bSol, cSol, _ := groth16.Solve(r1csHard, witness, proverOption)
	return Solution{A: aSol, B: bSol, C: cSol, Wires: wires}, err, nil
}
