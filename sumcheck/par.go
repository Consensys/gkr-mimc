package sumcheck

import (
	"gkr-mimc/common"

	"github.com/consensys/gurvy/bn256/fr"
)

type indexedProver struct {
	I int
	P Prover
}

// ProveMultiThreaded runs a prover with multi-threading
func (p *Prover) ProveMultiThreaded(nChunk int) (proof Proof, qPrime, qL, qR, finalClaims []fr.Element) {

	// Define usefull constants
	n := len(p.eq.Table)     // Number of subcircuit. Since we haven't fold on h' yet
	g := len(p.vR.Table) / n // SubCircuit size. Since we haven't fold on hR yet
	bN := common.Log2(n)
	bG := common.Log2(g)
	logNChunk := common.Log2(nChunk)

	// Initialized the results
	proof.PolyCoeffs = make([][]fr.Element, bN+2*bG)
	qPrime = make([]fr.Element, bN)
	qL = make([]fr.Element, bG)
	qR = make([]fr.Element, bG)
	finalClaims = make([]fr.Element, 3+len(p.staticTables))

	// Initialize the channels
	evalsChan := make(chan []fr.Element, nChunk)
	finChan := make(chan indexedProver, nChunk)
	rChans := make([]chan fr.Element, nChunk)

	// Starts the sub-provers
	for i := 0; i < nChunk; i++ {
		rChans[i] = make(chan fr.Element, 1)
		go p.RunForChunk(i, nChunk, evalsChan, rChans[i], finChan)
	}

	// Process on all values until all the subprover are completely fold
	for i := 0; i < 2*bG+bN-logNChunk; i++ {
		evals := ConsumeAccumulate(evalsChan, nChunk)
		proof.PolyCoeffs[i] = common.InterpolateOnRange(evals)
		r := common.GetChallenge(proof.PolyCoeffs[i])
		Broadcast(rChans, r)
		if i < bG {
			qL[i] = r
		} else if i < 2*bG {
			qR[i-bG] = r
		} else {
			qPrime[i-2*bG] = r
		}
	}

	p.ConsumeMergeProvers(finChan, nChunk)

	// Finishes on hPrime. Identical to the single-threaded implementation
	for i := 2*bG + bN - logNChunk; i < bN+2*bG; i++ {
		evals := p.GetEvalsOnHPrime()
		proof.PolyCoeffs[i] = common.InterpolateOnRange(evals)
		r := common.GetChallenge(proof.PolyCoeffs[i])
		p.FoldHPrime(r)
		qPrime[i-2*bG] = r
	}

	finalClaims[0] = p.vL.Table[0]
	finalClaims[1] = p.vR.Table[0]
	finalClaims[2] = p.eq.Table[0]
	for i, bkt := range p.staticTables {
		finalClaims[3+i] = bkt.Table[0]
	}

	close(evalsChan)
	close(finChan)

	return proof, qPrime, qL, qR, finalClaims

}

// ConsumeMergeProvers reallocate the provers from the content of the indexed prover,
// by concatenating their bookkeeping tables.
func (p *Prover) ConsumeMergeProvers(ch chan indexedProver, nToMerge int) {

	// Allocate the new Table
	newVL := make([]fr.Element, nToMerge)
	newVR := make([]fr.Element, nToMerge)
	newEq := make([]fr.Element, nToMerge)

	indexed := <-ch
	// First off the loop to take the static tables at the same time
	newVL[indexed.I] = indexed.P.vL.Table[0]
	newVR[indexed.I] = indexed.P.vR.Table[0]
	newEq[indexed.I] = indexed.P.eq.Table[0]
	// All subProvers have the same staticTables. So we can take the first one
	p.staticTables = indexed.P.staticTables

	for i := 0; i < nToMerge-1; i++ {
		indexed = <-ch
		newVL[indexed.I] = indexed.P.vL.Table[0]
		newVR[indexed.I] = indexed.P.vR.Table[0]
		newEq[indexed.I] = indexed.P.eq.Table[0]
	}

	p.vL = NewBookKeepingTable(newVL)
	p.vR = NewBookKeepingTable(newVR)
	p.eq = NewBookKeepingTable(newEq)

}

// ConsumeAccumulate consumes `nToConsume` elements from `ch`,
// and return their sum Element-wise
func ConsumeAccumulate(ch chan []fr.Element, nToConsume int) []fr.Element {
	res := <-ch
	for i := 0; i < nToConsume-1; i++ {
		tmp := <-ch
		for i := range res {
			res[i].Add(&res[i], &tmp[i])
		}
	}
	return res
}

// Broadcast broadcasts r, to all channels
func Broadcast(chs []chan fr.Element, r fr.Element) {
	for _, ch := range chs {
		ch <- r
	}
}

// RunForChunk runs thread with a partial prover
func (p *Prover) RunForChunk(
	chunkIndex, nChunk int,
	evalsChan chan []fr.Element,
	rChan chan fr.Element,
	finChan chan indexedProver,
) {
	// Deep-copies the static tables
	staticTablesCopy := make([]BookKeepingTable, len(p.staticTables))
	for i := range staticTablesCopy {
		staticTablesCopy[i] = p.staticTables[i].DeepCopy()
	}

	subProver := NewProver(
		p.vL.InterleavedChunk(chunkIndex, nChunk),
		p.vR.InterleavedChunk(chunkIndex, nChunk),
		p.eq.InterleavedChunk(chunkIndex, nChunk),
		p.gates,
		staticTablesCopy,
	)

	// Define usefull constants
	n := len(subProver.eq.Table)     // Number of subcircuit. Since we haven't fold on h' yet
	g := len(subProver.vR.Table) / n // SubCircuit size. Since we haven't fold on hR yet
	bN := common.Log2(n)
	bG := common.Log2(g)

	// Run on hL
	for i := 0; i < bG; i++ {
		evalsChan <- subProver.GetEvalsOnHL()
		r := <-rChan
		subProver.FoldHL(r)
	}

	// Run on hR
	for i := 0; i < bG; i++ {
		evalsChan <- subProver.GetEvalsOnHR()
		r := <-rChan
		subProver.FoldHR(r)
	}

	// Run on hPrime
	for i := 0; i < bN; i++ {
		evalsChan <- subProver.GetEvalsOnHPrime()
		r := <-rChan
		subProver.FoldHPrime(r)
	}

	finChan <- indexedProver{I: chunkIndex, P: subProver}
	close(rChan)
}
