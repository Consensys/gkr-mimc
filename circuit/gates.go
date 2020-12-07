package circuit

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gurvy/bn256/fr"
)

// EvaluateCombinator evaluate eq * \sum_i{ statics_i * gates_i(vL, vR) }
func EvaluateCombinator(vL, vR, eq fr.Element, gates []Gate, statics []fr.Element) fr.Element {
	var tmp, res fr.Element
	for i := range gates {
		gates[i].Eval(&tmp, vL, vR)
		tmp.Mul(&statics[i], &tmp)
		res.Add(&res, &tmp)
	}
	res.Mul(&res, &eq)
	return res
}

// Gate assumes the gate can only have 2 inputs
type Gate interface {
	// ID returns an ID that is unique for the gate
	ID() string
	// GnarkEval performs the same computation as Eval but on Gnark variables
	GnarkEval(cs *frontend.ConstraintSystem, vL, vR frontend.Variable)
	// Eval returns an evaluation for a unique pair of Eval
	Eval(res *fr.Element, vL, vR fr.Element)
	// EvalManyVL returns multiple evaluations with the same vR
	EvalManyVL(res, vLs []fr.Element, vR fr.Element)
	// EvalManyVR returns multiple evaluations with the same vL
	EvalManyVR(res []fr.Element, vL fr.Element, vRs []fr.Element)
	// Degrees returns the degrees of the gate relatively to HL, HR, HPrime
	Degrees() (degHL, degHR, degHPrime int)
}

// AddGate performs an addition
type AddGate struct{}

// Eval return the result vL + vR
func (a AddGate) Eval(res *fr.Element, vL, vR fr.Element) {
	res.Add(&vL, &vR)
}

// EvalManyVR performs an element-wise addition of many vRs values by one vL value
// res must be initialized with the same size as vRs
func (a AddGate) EvalManyVR(res []fr.Element, vL fr.Element, vRs []fr.Element) {
	for i, vR := range vRs {
		res[i].Add(&vL, &vR)
	}
}

// EvalManyVL performs an element-wise addition of many vLs values by one vR value
func (a AddGate) EvalManyVL(res []fr.Element, vLs []fr.Element, vR fr.Element) {
	for i, vL := range vLs {
		res[i].Add(&vL, &vR)
	}
}

// Degrees returns the degrees of the gate on hL, hR and hPrime
func (a AddGate) Degrees() (degHL, degHR, degHPrime int) {
	return 1, 1, 1
}

// MulGate performs a multiplication
type MulGate struct{}

// Eval returns vL * vR
func (m MulGate) Eval(res *fr.Element, vL, vR fr.Element) {
	res.Mul(&vL, &vR)
}

// EvalManyVR performs an element-wise multiplication of many vRs values by one vL value
func (m MulGate) EvalManyVR(res []fr.Element, vL fr.Element, vRs []fr.Element) {
	for i, vR := range vRs {
		res[i].Mul(&vL, &vR)
	}
}

// EvalManyVL performs an element-wise multiplication of many vLs values by one vR value
func (m MulGate) EvalManyVL(res, vLs []fr.Element, vR fr.Element) {
	for i, vL := range vLs {
		res[i].Mul(&vL, &vR)
	}
}

// Degrees returns the degrees of the gate on hL, hR and hPrime
func (m MulGate) Degrees() (degHL, degHR, degHPrime int) {
	return 1, 1, 2
}

// CopyGate performs a copy of the vL value and ignores the vR value
type CopyGate struct{}

// Eval returns vL
func (c CopyGate) Eval(res *fr.Element, vL, vR fr.Element) {
	*res = vL
}

// EvalManyVR performs an element-wise copy of vL for many vRs. (ignoring the values of the vRs)
func (c CopyGate) EvalManyVR(res []fr.Element, vL fr.Element, vRs []fr.Element) {
	for i := range vRs {
		res[i] = vL
	}
}

// EvalManyVL performs an element-wise copy of many vLs values
func (c CopyGate) EvalManyVL(res, vLs []fr.Element, vR fr.Element) {
	for i := range vLs {
		res[i] = vLs[i]
	}
}

// Degrees returns the degrees of the gate on hL, hR and hPrime
func (c CopyGate) Degrees() (degHL, degHR, degHPrime int) {
	return 1, 0, 1
}

// CipherGate cipher gate returns vL + (vR + c)^7
type CipherGate struct {
	Ark fr.Element
}

// Eval returns vL + (vR + c)^7
func (c CipherGate) Eval(res *fr.Element, vL, vR fr.Element) {
	// tmp = vR + Ark
	tmp := vR
	tmp.Add(&tmp, &c.Ark)
	// res = tmp^7
	*res = tmp
	res.Square(res)
	res.Mul(res, &tmp)
	res.Square(res)
	res.Mul(res, &tmp)
	// Then add vL
	res.Add(res, &vL)
}

// EvalManyVR performs cipher evaluations of many vRs values by one vL value
// Nothing special to do here
func (c CipherGate) EvalManyVR(res []fr.Element, vL fr.Element, vRs []fr.Element) {
	for i, vR := range vRs {
		c.Eval(&res[i], vL, vR)
	}
}

// EvalManyVL performs an element-wise cipher of many vLs values by one vR
// This one is optimized to only do the vL exponentiation once
func (c CipherGate) EvalManyVL(res, vLs []fr.Element, vR fr.Element) {
	// tmp = vR + Ark
	tmp := vR
	tmp.Add(&tmp, &c.Ark)
	// right = tmp^7
	right := tmp
	right.Square(&right)
	right.Mul(&right, &tmp)
	right.Square(&right)
	right.Mul(&right, &tmp)

	for i, vL := range vLs {
		res[i].Add(&right, &vL)
	}
}

// Degrees returns the degrees of the gate on hL, hR and hPrime
func (c CipherGate) Degrees() (degHL, degHR, degHPrime int) {
	return 1, 7, 7
}
