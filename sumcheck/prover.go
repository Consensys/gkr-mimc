package sumcheck

import (
	"fmt"
	"runtime"

	"github.com/consensys/gkr-mimc/circuit"
	"github.com/consensys/gkr-mimc/common"
	"github.com/consensys/gkr-mimc/poly"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

// Minimal size of chunks before considering parallelization for a task
const (
	foldingMinTaskSize     int = 1 << 10
	partialEvalMinTaskSize int = 1 << 6
	eqTableChunkSize       int = 1 << 8
	addInplaceMinChunkSize int = 1 << 10
)

// Proof is the object produced by the prover
type Proof [][]fr.Element

// Prove contains the coordination logic for all workers contributing to a (multi)-sumcheck proof
// The sum "proven" by the sumchecks is the following, for all `j`
//
// 		\sum_{i} eq(qPrime[j], i) * Gate(X[1][i], ..., X[n][i])
//
// INPUTS
//
// - `X[{k}][{i}]` is a double slice of field element. Each subslice `X[{k}]` represent a (multilinear) polynomial
//		being part of the sumcheck. Each of those is expressed as a slice of evaluation over the hypercube
//		in lexicographic order.
// - `qPrime[{j}]` is a multilinear variable (so a tuple of field element). For all `k` and `j` we must have
//		`2 ^ len(qPrime[j]) == len(X[k])
// - `claims` is the list of alleged values of each of the sum. We must have `len(claims) == len(qPrime)`. It is
//		only used for Fiat-Shamir
// - `gate` is a `circuit.Gate` object. It represents a low-degree multivariate polynomial.
//
// OUTPUTS
//
// - `proof` contains all the intermediate prover messages generated during the sumcheck protocol
// - `challenges` the challenges generated during the protocol
// - `claims` contains the evaluation of each X_{i}(challenges). The last entry is the evaluation
//		of `eq(qPrime, challenges)`
func Prove(X []poly.MultiLin, qPrimes [][]fr.Element, claims []fr.Element, gate circuit.Gate) (proof Proof, challenges, finalClaims []fr.Element) {

	// Define usefull constants & initializes the instance
	bN := len(qPrimes[0])

	// Sanity-checks : all X should have length 1<<bn
	for i, x := range X {
		if len(x) != 1<<bN {
			panic(fmt.Sprintf("inconsistent sizes : bn is %v but table %v has size %v", bN, i, len(x)))
		}
	}

	inst := makeInstance(X, gate)
	// Initialized the results
	proof = make(Proof, bN)
	challenges = make([]fr.Element, bN)

	// 8 . runtime.NumCPU() -> To be sure, this will never clog
	callback := make(chan []fr.Element, 8*runtime.NumCPU())

	// Precomputes the eq table
	makeEqTable(inst, claims, qPrimes, callback)

	// Run on hPrime
	for k := 0; k < bN; k++ {
		evals := dispatchPartialEvals(inst, callback)
		proof[k] = poly.InterpolateOnRange(evals)
		r := common.GetChallenge(proof[k])
		dispatchFolding(inst, r, callback)
		challenges[k] = r
	}

	// Save the final claims on each poly and dump the polys
	finalClaims = make([]fr.Element, 0, len(inst.X)+1)
	finalClaims = append(finalClaims, inst.Eq[0])
	poly.DumpLarge(inst.Eq)

	for _, x := range inst.X {
		finalClaims = append(finalClaims, x[0])
		poly.DumpLarge(x)
	}

	return proof, challenges, finalClaims

}

// initializeInstance returns an instance with L, R, gates, and degree sets
func makeInstance(X []poly.MultiLin, gate circuit.Gate) *instance {
	n := len(X[0])
	return &instance{X: X, Eq: poly.MakeLarge(n), gate: gate, degree: gate.Degree() + 1}

}

// creates the eq table for the current instance, with possibly many claims at different points
// If there are multiple claims and evaluations points, then it returns a random linear combination's
// coefficients of the claims and qPrime
func makeEqTable(
	inst *instance,
	claims []fr.Element, qPrimes [][]fr.Element,
	callback chan []fr.Element,
) (rnd fr.Element) {

	if callback == nil {
		// If no callback is provided, create one on the spot
		callback = make(chan []fr.Element, 8*runtime.NumCPU())
	}

	if len(claims) != len(qPrimes) && len(qPrimes) > 1 {
		panic(fmt.Sprintf("provided a multi-instance %v but only the number of claim does not match %v", len(qPrimes), len(claims)))
	}

	// First generate the eq table for the first qPrime directly inside the instance
	dispatchEqTable(inst, qPrimes[0], callback)

	// Only one claim => no random linear combinations
	if len(claims) < 1 {
		return fr.Element{}
	}

	// Else generate a random coefficient x
	// The random linear combination will be of the form
	// C = a0 + a1*r + a2*r^2 + a3*r^3 which will be enough
	initialMultiplier := common.GetChallenge(claims)
	multiplier := initialMultiplier

	// Initializes a dummy instance with just an eqTable
	tmpInst := &instance{Eq: poly.MakeLarge(1 << len(qPrimes[0]))}

	for i := 1; i < len(qPrimes); i++ {
		dispatchEqTable(tmpInst, qPrimes[i], callback, multiplier)
		dispatchAdditions(callback, inst.Eq, tmpInst.Eq)
		multiplier.Mul(&multiplier, &initialMultiplier)
	}

	poly.DumpLarge(tmpInst.Eq)

	// Returns the seed of the linear combination
	return initialMultiplier
}

// Calls the partial evals by calling the worker pool if that's usefull
// evalChan is passed for reuse purpose
func dispatchPartialEvals(inst *instance, callback chan []fr.Element) []fr.Element {
	mid := len(inst.Eq) / 2

	nTasks := common.TryDispatch(mid, partialEvalMinTaskSize, func(start, stop int) {
		jobQueue <- createPartialEvalJob(inst, callback, start, stop)
	})

	// `0` means the tasks where not dispatched as it
	// deemed unprofitable to parallelize this task
	if nTasks < 1 {
		return inst.getPartialPolyChunk(0, mid)
	}

	// Otherwise consumes happily the callback channel and return the eval
	return consumeAccumulate(callback, nTasks)
}

// Calls the folding by either passing to the worker pool if this is deemed usefull
// or synchronously if not
func dispatchFolding(inst *instance, r fr.Element, callback chan []fr.Element) {
	mid := len(inst.Eq) / 2

	nbTasks := common.TryDispatch(mid, foldingMinTaskSize, func(start, stop int) {
		jobQueue <- createFoldingJob(inst, callback, r, start, stop)
	})

	// `0` means the tasks where not dispatched as it
	// deemed unprofitable to parallelize this task
	if nbTasks < 1 {
		inst.foldChunk(r, 0, mid)
	} else {
		// Otherwise, wait for all callback to be done
		for i := 0; i < nbTasks; i++ {
			<-callback
		}
	}

	// Finallly cut in half the tables
	inst.Eq = inst.Eq[:mid]
	for i := range inst.X {
		inst.X[i] = inst.X[i][:mid]
	}
}

// Computes the eq table for the comming round
func dispatchEqTable(inst *instance, qPrime []fr.Element, callback chan []fr.Element, multiplier ...fr.Element) {
	nbChunks := len(inst.Eq) / eqTableChunkSize

	// No need to fix limit size of the batch as it already done
	minTaskSize := 1
	nbTasks := common.TryDispatch(nbChunks, minTaskSize, func(start, stop int) {
		jobQueue <- createEqTableJob(inst, callback, qPrime, start, stop, multiplier...)
	})

	if nbTasks < 1 {
		// All in one chunk
		poly.FoldedEqTable(inst.Eq, qPrime, multiplier...)
		return
	}

	// Otherwise, wait for all callback to be done
	for i := 0; i < nbTasks; i++ {
		<-callback
	}
}

// Dispatch the addition of two bookkeeping table to be run in parallel
func dispatchAdditions(callback chan []fr.Element, a, b poly.MultiLin) {
	// Attempts running in the pool
	nbTasks := common.TryDispatch(len(a), addInplaceMinChunkSize, func(start, stop int) {
		jobQueue <- createAdditionJob(callback, a, b, start, stop)
	})

	// The pool returning 0 means you need to run it monothreaded
	if nbTasks < 1 {
		// All in one chunk
		addInPlace(a, b, 0, len(a))
		return
	}

	// Otherwise, wait for all callback to be done
	for i := 0; i < nbTasks; i++ {
		<-callback
	}
}

// ConsumeAccumulate consumes `nToConsume` elements from `ch`,
// and return their sum Element-wise
func consumeAccumulate(ch chan []fr.Element, nToConsume int) []fr.Element {
	res := <-ch
	for i := 0; i < nToConsume-1; i++ {
		tmp := <-ch
		for i := range res {
			res[i].Add(&res[i], &tmp[i])
		}
	}
	return res
}
