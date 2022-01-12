package gates

import (
	"github.com/AlexandreBelling/gnarkfrontend"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
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

// EvalManyVR performs an element-wise copy of vL for many vRs. (ignoring the values of the vRs)
func (c CopyGate) EvalManyVR(res []fr.Element, vL *fr.Element, vRs []fr.Element) {
	for i := range vRs {
		res[i].Set(vL)
	}
}

// EvalManyVL performs an element-wise copy of many vLs values
func (c CopyGate) EvalManyVL(res, vLs []fr.Element, vR *fr.Element) {
	copy(res, vLs)
}

// Degrees returns the degrees of the gate on hL, hR and hPrime
func (c CopyGate) Degrees() (degHL, degHR, degHPrime int) {
	return 1, 0, 1
}
