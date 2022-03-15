package polynomial

import (
	"fmt"

	"github.com/AlexandreBelling/gnark/frontend"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

// Univariate encodes a univariate polynomial: a0 + a1X + ... + ad X^d <=> {a0, a1, ... , ad}
type Univariate []frontend.Variable

// NewUnivariate is the default constructor
func NewUnivariate(coeffs []frontend.Variable) Univariate {
	return coeffs
}

// AllocateUnivariate returns an empty multilinear with a given size
func AllocateUnivariate(degree int) Univariate {
	return NewUnivariate(make([]frontend.Variable, degree+1))
}

// Assign value to a previously allocated univariate
func (u Univariate) Assign(coeffs []fr.Element) {
	if len(coeffs) != len(u) {
		panic(fmt.Sprintf("Inconsistent assignment for univariate poly %v != %v", len(coeffs), len(u)))
	}
	for i, c := range coeffs {
		u[i] = c
	}
}

// Eval returns p(x)
func (u Univariate) Eval(cs frontend.API, x frontend.Variable) (res frontend.Variable) {

	res = frontend.Variable(0)
	aux := frontend.Variable(0)

	for i := len(u) - 1; i >= 0; i-- {
		if i != len(u)-1 {
			res = cs.Mul(aux, x)
		}
		aux = cs.Add(res, u[i])
	}

	// TODO why mul by 1 ?
	return cs.Mul(aux, 1)
}

// ZeroAndOne returns p(0) + p(1)
func (u Univariate) ZeroAndOne(cs frontend.API) frontend.Variable {
	res := cs.Add(u[0], u[0], u[1:]...)
	return res
}
