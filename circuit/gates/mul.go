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

// EvalManyVR performs an element-wise multiplication of many vRs values by one vL value
func (m MulGate) EvalManyVR(res []fr.Element, vL *fr.Element, vRs []fr.Element) {
	for i, vR := range vRs {
		res[i].Mul(vL, &vR)
	}
}

// EvalManyVL performs an element-wise multiplication of many vLs values by one vR value
func (m MulGate) EvalManyVL(res, vLs []fr.Element, vR *fr.Element) {
	for i, vL := range vLs {
		res[i].Mul(&vL, vR)
	}
}

// Degrees returns the degrees of the gate on hL, hR and hPrime
func (m MulGate) Degrees() (degHL, degHR, degHPrime int) {
	return 1, 1, 2
}
