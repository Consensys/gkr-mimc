package polynomial

import (
	"math/big"

	"github.com/consensys/gnark/backend/r1cs/r1c"
	"github.com/consensys/gnark/frontend"
)

// UnivariateEqEval computes f(q, h) = 1 - q - h + 2 * q * h
// It returns 1 if q == h \in {0, 1}
func UnivariateEqEval(cs *frontend.ConstraintSystem, q, h frontend.Variable) r1c.LinearExpression {
	res := cs.LinearExpression(
		cs.Term(cs.Mul(q, h), big.NewInt(2)),
		cs.Term(cs.Constant(1), big.NewInt(1)),
		cs.Term(q, big.NewInt(-1)),
		cs.Term(h, big.NewInt(-1)),
	)
	return res
}

// EqEval returns Eq(q', h')
func EqEval(cs *frontend.ConstraintSystem, qPrime, hPrime []frontend.Variable) frontend.Variable {
	res := cs.Constant(1)
	// multiply all the UnivariateEqEval's into res
	for i := range qPrime {
		res = cs.Mul(res, UnivariateEqEval(cs, qPrime[i], hPrime[i]))
	}
	return res
}
