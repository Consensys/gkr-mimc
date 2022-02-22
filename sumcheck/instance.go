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
func Evaluation(gate circuit.Gate, qPrime [][]fr.Element, claims []fr.Element, x ...poly.MultiLin) (res fr.Element) {

	inst_ := instance{X: x, gate: gate, degree: gate.Degree() + 1, Eq: poly.MakeLarge(1 << len(qPrime[0]))}
	makeEqTable(&inst_, claims, qPrime, nil)
	defer poly.DumpLarge(inst_.Eq)

	var tmp fr.Element
	buf := make([]*fr.Element, len(x))

	for n := range x[0] {
		for k := range x {
			buf[k] = &x[k][n]
		}
		gate.Eval(&tmp, buf...)
		tmp.Mul(&tmp, &inst_.Eq[n])
		res.Add(&res, &tmp)
	}

	return res
}
