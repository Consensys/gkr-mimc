package gates

import (
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/frontend"
)

// MulGate performs a multiplication
type MulGate struct{}

// ID returns the MulGate as ID
func (m MulGate) ID() string { return "MulGate" }

// Eval returns vL * vR
func (m MulGate) Eval(res *fr.Element, xs ...*fr.Element) {
	res.Mul(xs[0], xs[1])
}

// GnarkEval performs the gate operation on gnark variables
func (m MulGate) GnarkEval(cs frontend.API, xs ...frontend.Variable) frontend.Variable {
	return cs.Mul(xs[0], xs[1])
}

// Degree returns the Degree of the gate on hL, hR and hPrime
func (m MulGate) Degree() (degHPrime int) {
	return 2
}
