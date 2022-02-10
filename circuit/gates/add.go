package gates

import (
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/frontend"
)

// AddGate performs an addition
type AddGate struct{}

// ID returns the gate ID
func (a AddGate) ID() string { return "AddGate" }

// Eval return the result vL + vR
func (a AddGate) Eval(res, vL, vR *fr.Element) {
	res.Add(vL, vR)
}

// GnarkEval compute the gate on a gnark circuit
func (a AddGate) GnarkEval(cs frontend.API, vL, vR frontend.Variable) frontend.Variable {
	// Unoptimized, but unlikely to cause any significant performance loss
	return cs.Add(vL, vR)
}

// Degree returns the Degree of the gate on hL, hR and hPrime
func (a AddGate) Degree() (degHPrime int) {
	return 1
}
