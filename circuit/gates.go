package circuit

import (
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/frontend"
)

// Gate assumes the gate can only have 2 inputs
type Gate interface {
	// ID returns an ID that is unique for the gate
	ID() string
	// GnarkEval performs the same computation as Eval but on Gnark variables
	GnarkEval(cs frontend.API, xs ...frontend.Variable) frontend.Variable
	// Eval returns an evaluation for a unique pair of Eval
	Eval(res *fr.Element, xs ...*fr.Element)
	// Degree returns the degrees of the gate relatively to HL, HR, HPrime
	Degree() (degHPrime int)
}

// EvaluateCombinator evaluate eq * \sum_i{ statics_i * gates_i(vL, vR) }
func EvaluateCombinator(gate Gate, eq *fr.Element, xs ...*fr.Element) fr.Element {
	var tmp, res fr.Element
	gate.Eval(&tmp, xs...)
	res.Mul(&res, eq)
	return res
}
