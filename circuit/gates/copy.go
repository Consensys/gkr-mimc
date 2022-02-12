package gates

import (
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/frontend"
)

// IdentityGate performs a copy of the vL value and ignores the vR value
type IdentityGate struct{}

// ID returns "CopyGate" as an ID for CopyGate
func (c IdentityGate) ID() string { return "CopyGate" }

// Eval returns vL
func (c IdentityGate) Eval(res *fr.Element, xs ...*fr.Element) {
	res.Set(xs[0])
}

// GnarkEval performs the copy on gnark variable
func (c IdentityGate) GnarkEval(cs frontend.API, x ...frontend.Variable) frontend.Variable {
	return x[0]
}

// Degree returns the Degree of the gate on hL, hR and hPrime
func (c IdentityGate) Degree() (degHPrime int) {
	return 1
}
