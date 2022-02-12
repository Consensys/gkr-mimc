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
func (a AddGate) Eval(res *fr.Element, xs ...*fr.Element) {
	res.Add(xs[0], xs[1])
}

// GnarkEval compute the gate on a gnark circuit
func (a AddGate) GnarkEval(cs frontend.API, xs ...frontend.Variable) frontend.Variable {
	// Unoptimized, but unlikely to cause any significant performance loss
	return cs.Add(xs[0], xs[1])
}

// Degree returns the Degree of the gate on hL, hR and hPrime
func (a AddGate) Degree() (degHPrime int) {
	return 1
}
