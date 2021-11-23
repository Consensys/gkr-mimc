package gadget

import "github.com/consensys/gnark-crypto/ecc/bn254/fr"

type Solution struct {
	Wires, A, B, C []fr.Element
}

func (s *Solution) Fix() bool {

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
