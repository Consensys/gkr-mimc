package sumcheck

import (
	"github.com/consensys/gkr-mimc/polynomial"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

// Minimal size under which we do not consider multithreading the
const eqTableChunkSize int = 1 << 8

// The perform the folding operation for all the book keeping tables of the instance
func runFoldingJob(job *proverJob) {
	job.inst.foldChunk(job.r, job.start, job.stop)
	// We pass an empty array as a callback
	job.callback <- []fr.Element{}
}

func runPartialEval(job *proverJob) {
	// Defers to the chunked method and write the result in the callback channel
	job.callback <- job.inst.getPartialPolyChunk(job.start, job.stop)
}

func runEqTableJob(job *proverJob) {
	// Defers the chunked method for computing the eq table
	job.inst.computeEqTableJob(job.qPrime, job.start, job.stop)
	job.callback <- []fr.Element{}
}

// Performs the folding on a chunk synchronously
func (inst *instance) foldChunk(r fr.Element, start, stop int) {
	inst.Eq.FoldChunk(r, start, stop)
	inst.L.FoldChunk(r, start, stop)
	inst.R.FoldChunk(r, start, stop)
}

// Returns the partial poly only on a given portion
func (inst *instance) getPartialPolyChunk(start, stop int) []fr.Element {
	// Define usefull constants
	nEvals := inst.degree + 1
	mid := len(inst.Eq) / 2

	evals := make([]fr.Element, nEvals)
	var v, dL, dR, dEq fr.Element

	// Accumulates the combinator's result
	evalL := make([]fr.Element, nEvals)
	evalR := make([]fr.Element, nEvals)
	evalEq := make([]fr.Element, nEvals)

	for x := start; x < stop; x++ {

		// Computes the preEvaluations
		evalL[0] = inst.L[x]
		evalR[0] = inst.R[x]
		evalEq[0] = inst.Eq[x]

		dL.Sub(&inst.L[x+mid], &inst.L[x])
		dR.Sub(&inst.R[x+mid], &inst.R[x])
		dEq.Sub(&inst.Eq[x+mid], &inst.Eq[x])

		for t := 1; t < nEvals; t++ {
			evalL[t].Add(&evalL[t-1], &dL)
			evalR[t].Add(&evalR[t-1], &dR)
			evalEq[t].Add(&evalEq[t-1], &dEq)
		}

		for t := 0; t < nEvals; t++ {
			inst.gate.Eval(&v, &evalL[t], &evalR[t])
			v.Mul(&v, &evalEq[t])
			evals[t].Add(&evals[t], &v)
		}
	}

	return evals
}

// The size of a chunk is always assumed to be 1 << 12
// This matters because we need powers of two for this to work
func (inst *instance) computeEqTableJob(qPrime []fr.Element, start, stop int) {
	preallocatedEq := inst.Eq
	for chunkID := start; chunkID < stop; chunkID++ {
		// Just defers to the dedicated function
		polynomial.ChunkOfEqTable(preallocatedEq, chunkID, eqTableChunkSize, qPrime)
	}
}
