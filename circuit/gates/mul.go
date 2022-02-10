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
func (m MulGate) Eval(res, vL, vR *fr.Element) {
	res.Mul(vL, vR)
}

// GnarkEval performs the gate operation on gnark variables
func (m MulGate) GnarkEval(cs frontend.API, vL, vR frontend.Variable) frontend.Variable {
	return cs.Mul(vL, vR)
}

// Degree returns the Degree of the gate on hL, hR and hPrime
func (m MulGate) Degree() (degHPrime int) {
	return 2
}
