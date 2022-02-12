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
	X    []poly.MultiLin
	Eq   poly.MultiLin
	gate circuit.Gate
	// Overall degree of the sumcheck instance
	degree int
}

// Evaluate the instance of the sumcheck
func (inst *instance) Evaluation() (res fr.Element) {
	var tmp fr.Element
	buf := make([]*fr.Element, len(inst.X))

	for n := range inst.X[0] {
		for k := range inst.X {
			buf[k] = &inst.X[k][n]
		}
		inst.gate.Eval(&tmp, buf...)
		tmp.Mul(&tmp, &inst.Eq[n])
		res.Add(&res, &tmp)
	}

	return res
}
