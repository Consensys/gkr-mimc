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

// Prove contains the coordination logic for all workers contributing to the sumcheck proof
func Prove(L, R poly.MultiLin, qPrimes [][]fr.Element, claims []fr.Element, gate circuit.Gate) (proof Proof, challenges, finalClaims []fr.Element) {

	// Define usefull constants & initializes the instance
	bN := len(qPrimes[0])
	inst := makeInstance(L, R, gate)

	// Initialized the results
	proof = make(Proof, bN)
	challenges = make([]fr.Element, bN)
	finalClaims = make([]fr.Element, 3)

	// 8 . runtime.NumCPU() -> To be sure, this will never clog
	callback := make(chan []fr.Element, 8*runtime.NumCPU())

	// Precomputes the eq table
	makeEqTable(inst, callback, claims, qPrimes)

	// Run on hPrime
	for k := 0; k < bN; k++ {
		evals := dispatchPartialEvals(inst, callback)
		proof[k] = poly.InterpolateOnRange(evals)
		r := common.GetChallenge(proof[k])
		dispatchFolding(inst, r, callback)
		challenges[k] = r
	}

	if len(inst.L)+len(inst.R)+len(inst.Eq) > 3 {
		panic("did not fold all the tables")
	}

	// Final claim is
	finalClaims[0] = inst.L[0]
	finalClaims[1] = inst.R[0]
	finalClaims[2] = inst.Eq[0]

	poly.DumpInLargePool(inst.Eq)
	poly.DumpInLargePool(inst.L)
	poly.DumpInLargePool(inst.R)

	return proof, challenges, finalClaims

}

// initializeInstance returns an instance with L, R, gates, and degree sets
func makeInstance(L, R poly.MultiLin, gate circuit.Gate) *instance {
	n := len(L)
	return &instance{L: L, R: R, Eq: poly.MakeLargeFrSlice(n), gate: gate, degree: gate.Degree() + 1}

}

// creates the eq table for the current instance, with possibly many claims at different points
// If there are multiple claims and evaluations points, then it returns a random linear combination's
// coefficients of the claims and qPrime
func makeEqTable(
	inst *instance, callback chan []fr.Element,
	claims []fr.Element, qPrimes [][]fr.Element,
) (rnd fr.Element) {

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
	tmpInst := &instance{Eq: poly.MakeLargeFrSlice(1 << len(qPrimes[0]))}

	for i := 1; i < len(qPrimes); i++ {
		dispatchEqTable(tmpInst, qPrimes[i], callback, multiplier)
		dispatchAdditions(callback, inst.Eq, tmpInst.Eq)
		multiplier.Mul(&multiplier, &initialMultiplier)
	}

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
	inst.L = inst.L[:mid]
	inst.R = inst.R[:mid]
}

// Computes the eq table for the comming round
func dispatchEqTable(inst *instance, qPrime []fr.Element, callback chan []fr.Element, multiplier ...fr.Element) {
	nbChunks := len(inst.Eq) / eqTableChunkSize

	// No need to fix limit size of the batch as it already done
	minTaskSize := 1
	nbTasks := common.TryDispatch(nbChunks, minTaskSize, func(start, stop int) {
		jobQueue <- createEqTableJob(inst, callback, qPrime, start, stop)
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
