package gates

import (
	"github.com/AlexandreBelling/gnark/frontend"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
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

// EvalManyVR performs an element-wise addition of many vRs values by one vL value
// res must be initialized with the same size as vRs
func (a AddGate) EvalManyVR(res []fr.Element, vL *fr.Element, vRs []fr.Element) {
	for i, vR := range vRs {
		res[i].Add(vL, &vR)
	}
}

// EvalManyVL performs an element-wise addition of many vLs values by one vR value
func (a AddGate) EvalManyVL(res []fr.Element, vLs []fr.Element, vR *fr.Element) {
	for i, vL := range vLs {
		res[i].Add(&vL, vR)
	}
}

// Degrees returns the degrees of the gate on hL, hR and hPrime
func (a AddGate) Degrees() (degHL, degHR, degHPrime int) {
	return 1, 1, 1
}
