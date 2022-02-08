package sumcheck2

import (
	"runtime"

	"github.com/consensys/gkr-mimc/circuit"
	"github.com/consensys/gkr-mimc/common"
	"github.com/consensys/gkr-mimc/polynomial"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

// Proof is the object produced by the prover
type Proof [][]fr.Element

// Prove contains the coordination logic for all workers contributing to the sumcheck proof
func Prove(L, R polynomial.BookKeepingTable, qPrime []fr.Element, gate circuit.Gate) (proof Proof, challenges, finalClaims []fr.Element) {

	// Define usefull constants & initializes the instance
	bN := len(qPrime)
	n := 1 << bN // Number of subcircuit. Since we haven't fold on h' yet
	inst := makeInstance(L, R, gate)
	inst.Eq = make(polynomial.BookKeepingTable, n)

	// Initialized the results
	proof = make(Proof, bN)
	challenges = make([]fr.Element, bN)
	finalClaims = make([]fr.Element, 3)

	// 8 . runtime.NumCPU() -> To be sure, this will never clog
	callback := make(chan []fr.Element, 8*runtime.NumCPU())

	// Precomputes the eq table
	dispatchEqTable(inst, qPrime, callback)

	// Run on hPrime
	for k := 0; k < bN; k++ {
		evals := dispatchPartialEvals(inst, callback)
		proof[k] = polynomial.InterpolateOnRange(evals)
		r := common.GetChallenge(proof[k])
		dispatchFolding(inst, r, callback)
		challenges[k] = r
	}

	// Final claim is
	finalClaims[0] = inst.L[0]
	finalClaims[1] = inst.R[0]
	finalClaims[2] = inst.Eq[0]

	return proof, challenges, finalClaims

}

// Calls the partial evals by calling the worker pool if that's usefull
// evalChan is passed for reuse purpose
func dispatchPartialEvals(inst *instance, callback chan []fr.Element) []fr.Element {
	mid := len(inst.Eq) / 2

	// The value `minTaskSize` is purely empirical
	minTaskSize := 1 << 8
	nTasks := common.TryDispatch(mid, minTaskSize, func(start, stop int) {
		jobQueue <- &proverJob{
			type_: partialEval,
			start: start, stop: stop,
			inst:     inst,
			callback: callback,
		}
	})

	// `0` means the tasks where not dispatched as it
	// deemed unprofitable to parallelize this task
	if nTasks < 1 {
		return inst.getPartialPolyChunk(0, mid)
	}

	// Otherwise consumes happily the callback channel and return the eval
	return consumeAccumulate(callback, nTasks)
}

// initializeInstance returns an instance with L, R, gates, and degree sets
func makeInstance(L, R polynomial.BookKeepingTable, gate circuit.Gate) *instance {
	_, _, deg := gate.Degrees()
	n := len(L)
	return &instance{L: L, R: R, Eq: make(polynomial.BookKeepingTable, n), gate: gate, degree: deg + 1}

}

// Calls the folding by either passing to the worker pool if this is deemed usefull
// or synchronously if not
func dispatchFolding(inst *instance, r fr.Element, callback chan []fr.Element) {
	mid := len(inst.Eq) / 2

	// The value `minTaskSize` is purely empirical
	minTaskSize := 1 << 8
	nbTasks := common.TryDispatch(mid, minTaskSize, func(start, stop int) {
		jobQueue <- &proverJob{
			type_: folding,
			start: start, stop: stop,
			inst:     inst,
			callback: callback,
		}
	})

	// `0` means the tasks where not dispatched as it
	// deemed unprofitable to parallelize this task
	if nbTasks < 1 {
		inst.foldChunk(r, 0, mid)
		return
	}

	// Otherwise, wait for all callback to be done
	for i := 0; i < nbTasks; i++ {
		<-callback
	}

	// And cut in half the tables
	inst.Eq = inst.Eq[:mid]
	inst.L = inst.L[:mid]
	inst.R = inst.R[:mid]
}

// Computes the eq table for the comming round
func dispatchEqTable(inst *instance, qPrime []fr.Element, callback chan []fr.Element) {
	nbChunks := len(inst.Eq) / eqTableChunkSize

	// No need to fix limit size of the batch as it already done
	minTaskSize := 1
	nbTasks := common.TryDispatch(nbChunks, minTaskSize, func(start, stop int) {
		jobQueue <- &proverJob{
			type_:    eqTable,
			start:    start,
			stop:     stop,
			inst:     inst,
			qPrime:   qPrime,
			callback: callback,
		}
	})

	if nbTasks < 1 {
		polynomial.GetFoldedEqTable(qPrime, inst.Eq)
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
