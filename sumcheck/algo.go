package sumcheck

import (
	"github.com/consensys/gkr-mimc/common"
	"github.com/consensys/gkr-mimc/poly"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

const evalSubChunkSize int = 128

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

	// Contains the output of the algo
	evals := make([]fr.Element, nEvals)

	// The computation is done by sub-chunks, to allow trading memory for indirections
	// Here are the preallocations
	tmpEvals := poly.MakeSmall(evalSubChunkSize)
	tmpEqs := poly.MakeSmall(evalSubChunkSize)
	dEqs := poly.MakeSmall(evalSubChunkSize)
	tmpXs := poly.MakeSmall(evalSubChunkSize * nInputs)
	dXs := poly.MakeSmall(evalSubChunkSize * nInputs)

	defer poly.DumpSmall(tmpEvals)
	defer poly.DumpSmall(tmpEqs)
	defer poly.DumpSmall(dEqs)
	defer poly.DumpSmall(tmpXs)
	defer poly.DumpSmall(dXs)

	// Set of pointers to tmpXs that can be passed directly
	// to `gate.Evals`
	evaluationBuffer := make([][]fr.Element, nInputs)

	// For each subchunk
	for subChunkStart := start; subChunkStart < stop; subChunkStart += evalSubChunkSize {

		// Accounts for the fact that stop -start may not be divided by the sumc
		subChunkEnd := common.Min(subChunkStart+evalSubChunkSize, stop)
		subChunkLen := subChunkEnd - subChunkStart

		// Precomputations to save a few additions
		subChunkStartPlusMid := subChunkStart + mid
		subChunkEndPlusMid := subChunkEnd + mid
		nInputsSubChunkLen := nInputs * subChunkLen

		if subChunkLen < evalSubChunkSize {
			// Can only happen at the last iteration
			// Truncate the preallocated tables
			tmpEvals = tmpEvals[:subChunkLen]
			tmpEqs = tmpEqs[:subChunkLen]
			dEqs = dEqs[:subChunkLen]
			tmpXs = tmpXs[:subChunkLen*nInputs]
			dXs = dXs[:subChunkLen*nInputs]
		}

		// Special case: evaluation at t = 0

		// => directly use the values given in inst for Eq
		// So we don't do copies of Eq

		for k := 0; k < nInputs; k++ {
			// Redirect the evaluation table directly to inst
			// So we don't copy into tmpXs
			evaluationBuffer[k] = inst.X[k][subChunkStart:subChunkEnd]
		}

		// evaluate the gate with inputs pointed to by the evaluation buffer
		inst.gate.EvalBatch(tmpEvals, evaluationBuffer...)

		// Then update the evalsValue
		evalPtr := &evals[0] // 0 because t = 0
		var v fr.Element
		eqChunk := inst.Eq[subChunkStart:subChunkEnd]

		for x := 0; x < subChunkLen; x++ {
			v.Mul(&eqChunk[x], &tmpEvals[x])
			evalPtr.Add(evalPtr, &v)
		}

		// Second special case : evaluation at t = 1

		// => directly use the values given in inst for Eq
		// So we don't do copies of Eq

		for k := range inst.X {
			// Redirect the evaluation table directly to inst
			// So we don't copy into tmpXs
			evaluationBuffer[k] = inst.X[k][subChunkStartPlusMid:subChunkEndPlusMid]
		}

		// Recall that evaluationBuffer is a set of pointers to subslices of tmpXs
		inst.gate.EvalBatch(tmpEvals, evaluationBuffer...)

		// Then update the evalsValue
		evalPtr = &evals[1] // 1 because t = 1
		eqChunk = inst.Eq[subChunkStartPlusMid:subChunkEndPlusMid]

		for x := 0; x < subChunkLen; x++ {
			v.Mul(&eqChunk[x], &tmpEvals[x])
			evalPtr.Add(evalPtr, &v)
		}

		// Then regular case t >= 2

		// Initialize the eq and dEq table, at the value for t = 1
		// (We get the next values for t by adding dEqs)
		copy(tmpEqs, inst.Eq[subChunkStartPlusMid:subChunkEndPlusMid])
		for x := 0; x < subChunkLen; x++ {
			dEqs[x].Sub(&inst.Eq[subChunkStartPlusMid+x], &inst.Eq[subChunkStart+x])
		}

		for k := range inst.X {
			kOffset := k * subChunkLen

			// Initializes the dXs as P(t=1, x) - P(t=0, x)
			for x := 0; x < subChunkLen; x++ {
				dXs[kOffset+x].Sub(&inst.X[k][subChunkStartPlusMid+x], &inst.X[k][subChunkStart+x])
			}

			// As for eq, we initialize each input table `X` with the value for t = 1
			// (We get the next values for t by adding dXs)
			copy(tmpXs[kOffset:kOffset+subChunkLen], inst.X[k][subChunkStartPlusMid:subChunkEndPlusMid])

			// Also, we redirect the evaluation buffer over each subslice of tmpXs
			// So we can easily pass each of these values of to the `gates.EvalBatch` table
			evaluationBuffer[k] = tmpXs[kOffset : kOffset+subChunkLen]
		}

		for t := 2; t < nEvals; t++ {

			// Then update the evals at position t
			evalPtr = &evals[t]

			for x := 0; x < subChunkLen; x++ {
				tmpEqs[x].Add(&tmpEqs[x], &dEqs[x])
			}

			// Update the value of tmpXs : as dXs and tmpXs have the same layout,
			// no need to make a double loop on k : the index of the separate inputs
			// We can do this, because P is multilinear so P(t+1,x) = P(t, x) + dX(x)
			for kx := 0; kx < nInputsSubChunkLen; kx++ {
				tmpXs[kx].Add(&tmpXs[kx], &dXs[kx])
			}

			// Recall that evaluationBuffer is a set of pointers to subslices of tmpXs
			inst.gate.EvalBatch(tmpEvals, evaluationBuffer...)

			for x := 0; x < subChunkLen; x++ {
				v.Mul(&tmpEqs[x], &tmpEvals[x])
				evalPtr.Add(evalPtr, &v)
			}

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
