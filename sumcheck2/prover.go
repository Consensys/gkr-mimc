package sumcheck2

import (
	"runtime"

	"github.com/consensys/gkr-mimc/circuit"
	"github.com/consensys/gkr-mimc/common"
	"github.com/consensys/gkr-mimc/polynomial"
	"github.com/consensys/gkr-mimc/sumcheck"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

// Runs the sumcheck prover
func Prove(
	L, R polynomial.BookKeepingTable,
	evalAt []fr.Element,
	gate circuit.Gate,
) (proof sumcheck.Proof, q, finalClaims []fr.Element) {
	i := prepareInstance(L, R, evalAt, gate)
	return prove(&i)
}

// Prepare the instance to run `prove` on
func prepareInstance(L, R polynomial.BookKeepingTable,
	evalAt []fr.Element,
	gate circuit.Gate) instance {

	_, _, deg := gate.Degrees()

	i := instance{
		L: L, R: R,
		Eq:     polynomial.GetFoldedEqTable(evalAt),
		Gate:   gate,
		degree: deg + 1,
	}

	return i
}

// Runs the core meat of the prover sumcheck
func prove(i *instance) (proof sumcheck.Proof, q, finalClaims []fr.Element) {

	// Define usefull constants
	n := len(i.Eq) // Number of subcircuit. Since we haven't fold on h' yet
	bN := common.Log2Ceil(n)

	// Initialized the results
	proof.PolyCoeffs = make([][]fr.Element, bN)
	q = make([]fr.Element, bN)
	finalClaims = make([]fr.Element, 3)

	// Run on hPrime
	for k := 0; k < bN; k++ {
		evals := i.getPartialPoly()
		proof.PolyCoeffs[k] = polynomial.InterpolateOnRange(evals)
		r := common.GetChallenge(proof.PolyCoeffs[k])
		i.fold(r)
		q[k] = r
	}

	finalClaims[0] = i.L[0]
	finalClaims[1] = i.R[0]
	finalClaims[2] = i.Eq[0]

	return proof, q, finalClaims

}

func proveAsync(i *instance)

// Evaluates and return the partial polynomial of the sumcheck
func (i *instance) getPartialPoly() []fr.Element {

	// Define usefull constants
	nEvals := i.degree + 1
	mid := len(i.Eq) / 2

	evalChan := make(chan []fr.Element, runtime.NumCPU())

	nJob := common.ParallelizeNonBlocking(mid, func(start, stop int) {
		evals := make([]fr.Element, nEvals)
		var v, dL, dR, dEq fr.Element

		// Accumulates the combinator's result
		evalL := make([]fr.Element, nEvals)
		evalR := make([]fr.Element, nEvals)
		evalEq := make([]fr.Element, nEvals)

		for x := start; x < stop; x++ {

			// Computes the preEvaluations
			evalL[0] = i.L[x]
			evalR[0] = i.R[x]
			evalEq[0] = i.Eq[x]

			dL.Sub(&i.L[x+mid], &i.L[x])
			dR.Sub(&i.R[x+mid], &i.R[x])
			dEq.Sub(&i.Eq[x+mid], &i.Eq[x])

			for t := 1; t < nEvals; t++ {
				evalL[t].Add(&evalL[t-1], &dL)
				evalR[t].Add(&evalR[t-1], &dR)
				evalEq[t].Add(&evalEq[t-1], &dEq)
			}

			for t := 0; t < nEvals; t++ {
				i.Gate.Eval(&v, &evalL[t], &evalR[t])
				v.Mul(&v, &evalEq[t])
				evals[t].Add(&evals[t], &v)
			}
		}

		evalChan <- evals
	})

	// Collect the result of each thread
	eval := <-evalChan
	for j := 1; j < nJob; j++ {
		otherEval := <-evalChan
		for t := range eval {
			eval[t].Add(&eval[t], &otherEval[t])
		}
	}

	return eval
}

// Fold all the tables
func (i *instance) fold(r fr.Element) {
	i.L.Fold(r)
	i.R.Fold(r)
	i.Eq.Fold(r)
}
