package gates

import (
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/frontend"
)

// CopyGate performs a copy of the vL value and ignores the vR value
type CopyGate struct{}

// ID returns "CopyGate" as an ID for CopyGate
func (c CopyGate) ID() string { return "CopyGate" }

// Eval returns vL
func (c CopyGate) Eval(res, vL, vR *fr.Element) {
	res.Set(vL)
	// *res = vL
}

// GnarkEval performs the copy on gnark variable
func (c CopyGate) GnarkEval(cs frontend.API, vL, vR frontend.Variable) frontend.Variable {
	return vL
}

// Degree returns the Degree of the gate on hL, hR and hPrime
func (c CopyGate) Degree() (degHPrime int) {
	return 1
}
