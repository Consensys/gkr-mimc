package sumcheck

import (
	"github.com/consensys/gkr-mimc/poly"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

// Returns a closure to perform a chunk of folding
func createFoldingJob(inst *instance, callback chan []fr.Element, r fr.Element, start, stop int) func() {
	return func() {
		inst.foldChunk(r, start, stop)
		// We pass an empty array as a callback
		callback <- []fr.Element{}
	}
}

// Returns a closure to perform a chunk of partial evaluation
func createPartialEvalJob(inst *instance, callback chan []fr.Element, start, stop int) func() {
	return func() {
		// Defers to the chunked method and write the result in the callback channel
		callback <- inst.getPartialPolyChunk(start, stop)
	}
}

// Returns a closure to perform a chunk of eqTable job
func createEqTableJob(inst *instance, callback chan []fr.Element, qPrime []fr.Element, start, stop int, multiplier ...fr.Element) func() {
	return func() {
		// Defers the chunked method for computing the eq table
		inst.computeEqTableJob(qPrime, start, stop, multiplier...)
		callback <- []fr.Element{}
	}
}

// Returns a closure to perform a partial summation of two bookeeping tables
func createAdditionJob(callback chan []fr.Element, a, b poly.MultiLin, start, stop int) func() {
	return func() {
		addInPlace(a, b, start, stop)
		callback <- []fr.Element{}
	}
}

// Performs the folding on a chunk synchronously
func (inst *instance) foldChunk(r fr.Element, start, stop int) {
	inst.Eq.FoldChunk(r, start, stop)
	for _, x := range inst.X {
		x.FoldChunk(r, start, stop)
	}
}

// Returns the partial poly only on a given portion
func (inst *instance) getPartialPolyChunk(start, stop int) []fr.Element {
	// Define usefull constants
	nEvals := inst.degree + 1
	nInputs := len(inst.X)
	mid := len(inst.Eq) / 2

	evals := make([]fr.Element, nEvals)
	buf := make([]*fr.Element, nInputs)

	var v, dEq, dX fr.Element

	// Accumulates the combinator's result
	evalXs := make([]fr.Element, nEvals*nInputs)
	evalEq := make([]fr.Element, nEvals)

	for x := start; x < stop; x++ {

		// Preevaluate the eq table
		evalEq[0] = inst.Eq[x]
		dEq.Sub(&inst.Eq[x+mid], &inst.Eq[x])

		for t := 1; t < nEvals; t++ {
			evalEq[t].Add(&evalEq[t-1], &dEq)
		}

		// Computes the preEvaluations for the inputs tables
		for k := range inst.X {
			evalXs[0+k*nEvals] = inst.X[k][x]
			dX.Sub(&inst.X[k][x+mid], &inst.X[k][x])

			for t := 1; t < nEvals; t++ {
				offset := k * nEvals
				evalXs[t+offset].Add(&evalXs[t-1+offset], &dX)
			}
		}

		for t := 0; t < nEvals; t++ {

			for k := range inst.X {
				buf[k] = &evalXs[t+k*nEvals]
			}

			inst.gate.Eval(&v, buf...)
			v.Mul(&v, &evalEq[t])
			evals[t].Add(&evals[t], &v)
		}
	}

	return evals
}

// The size of a chunk is always assumed to be 1 << 12
// This matters because we need powers of two for this to work
func (inst *instance) computeEqTableJob(qPrime []fr.Element, start, stop int, multiplier ...fr.Element) {
	preallocatedEq := inst.Eq
	for chunkID := start; chunkID < stop; chunkID++ {
		// Just defers to the dedicated function
		poly.ChunkOfEqTable(preallocatedEq, chunkID, eqTableChunkSize, qPrime, multiplier...)
	}
}

// Add the second table into the first one for a given chunk
// b is unchanged
func addInPlace(a, b poly.MultiLin, start, stop int) {
	for i := start; i < stop; i++ {
		a[i].Add(&a[i], &b[i])
	}
}
