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
	// EvalBatch returns an evaluation for a range of inputs passed in evals
	// And puts each result in res
	EvalBatch(res []fr.Element, xs ...[]fr.Element)

	// Eval returns an evaluation for a unique pair of Eval
	Eval(res *fr.Element, xs ...*fr.Element)

	// Degree returns the degrees of the gate relatively to HL, HR, HPrime
	Degree() (degHPrime int)
}
