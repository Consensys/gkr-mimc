package polynomial

import (
	"fmt"
	"math/big"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gurvy/bn256/fr"
)

// Univariate encodes a univariate polynomial: a0 + a1X + ... + ad X^d <=> {a0, a1, ... , ad}
type Univariate struct {
	Coefficients []frontend.Variable
}

// NewUnivariate is the default constructor
func NewUnivariate(coeffs []frontend.Variable) Univariate {
	return Univariate{Coefficients: coeffs}
}

// AllocateUnivariate returns an empty multilinear with a given size
func AllocateUnivariate(degree int) Univariate {
	return NewUnivariate(make([]frontend.Variable, degree+1))
}

// Assign value to a previously allocated univariate
func (u *Univariate) Assign(coeffs []fr.Element) {
	if len(coeffs) != len(u.Coefficients) {
		panic(fmt.Sprintf("Inconsistent assignment for univariate poly %v != %v", len(coeffs), len(u.Coefficients)))
	}
	for i, c := range coeffs {
		u.Coefficients[i].Assign(c)
	}
}

// Eval returns p(x)
func (u *Univariate) Eval(cs *frontend.ConstraintSystem, x frontend.Variable) (res frontend.Variable) {

	res = cs.Constant(0)

	aux := cs.LinearExpression(
		cs.Term(cs.Constant(0), big.NewInt(0)),
	)

	for i := len(u.Coefficients) - 1; i >= 0; i-- {
		if i != len(u.Coefficients)-1 {
			res = cs.Mul(aux, x)
		}
		aux = cs.LinearExpression(
			cs.Term(res, big.NewInt(1)),
			cs.Term(u.Coefficients[i], big.NewInt(1)),
		)
	}

	return cs.Mul(aux, cs.Constant(1))
}

// ZeroAndOne returns p(0) + p(1)
func (u *Univariate) ZeroAndOne(cs *frontend.ConstraintSystem) frontend.Variable {

	// coeffsInterface is required for cs.Add(a, b, coeffsInterface[1:]...) to be accepted.
	coeffsInterface := make([]interface{}, len(u.Coefficients))
	for i, coeff := range u.Coefficients {
		coeffsInterface[i] = coeff
	}

	res := cs.Add(u.Coefficients[0], u.Coefficients[0], coeffsInterface[1:]...)

	return res
}
