package sumcheck

import (
	"github.com/consensys/gkr-mimc/circuit"
	"github.com/consensys/gkr-mimc/poly"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

// instance represents a sumcheck multivariate polynomials evaluation
// gi(X) = \sum_{Y} (eq(X, Y) Gi(ai(Y), bi(Y))
// X is the evaluation point
type instance struct {
	L, R, Eq poly.MultiLin
	gate     circuit.Gate
	// Overall degree of the sumcheck instance
	degree int
}

// Evaluate the instance of the sumcheck
func (i *instance) Evaluation() (res fr.Element) {
	var tmp fr.Element
	for n := range i.L {
		i.gate.Eval(&tmp, &i.L[n], &i.R[n])
		tmp.Mul(&tmp, &i.Eq[n])
		res.Add(&res, &tmp)
	}
	return res
}
