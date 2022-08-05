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

// Evaluate a sumcheck's sum. IT IS ONLY USED FOR TESTING.
// The sum "proven" by the sumchecks is the following, for all `j`
//
// 		\sum_{i} eq(qPrime[j], i) * Gate(X[1][i], ..., X[n][i])
//
// For multiple qPrimes, the protocol does not return multiple values
// but instead a `deterministic` random linear combination.
//
// INPUTS
//
// - `gate` is a `circuit.Gate` object. It represents a low-degree multivariate polynomial.
// - `qPrime[{j}]` is a multilinear variable (so a tuple of field element). For all `k` and `j` we must have
//		`2 ^ len(qPrime[j]) == len(X[k])
// - `the claims`, this makes the function useless. But in practice it helps for testing because
//		it will try to get the same result
// - `x[{k}][{i}]` is a double slice of field element. Each subslice `X[{k}]` represent a (multilinear) polynomial
//		being part of the sumcheck. Each of those is expressed as a slice of evaluation over the hypercube
//		in lexicographic order.
//
// OUTPUT
//
// - a single field element, the random linear combination of all the obtained claim
//
// IMPROVEMENTS
//
// The function could be improved by using `transcript.FiatShamir` from gnark. Or just take
// the coefficient of the random linear combination as inputs. Or just return all the claim
// instead of taking them as inputs.
//
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
