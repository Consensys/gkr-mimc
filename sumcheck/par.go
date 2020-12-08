package sumcheck

import (
	"gkr-mimc/common"
	"gkr-mimc/polynomial"

	"github.com/consensys/gurvy/bn256/fr"
)

// MultiThreadedProver can process on several threads
type MultiThreadedProver struct {
	// Contains the values of the previous layer
	vL []polynomial.BookKeepingTable
	vR []polynomial.BookKeepingTable
	// Contains the static tables defining the circuit structure
	eq           []polynomial.BookKeepingTable
	gates        []Gate
	staticTables []polynomial.BookKeepingTable
	// Degrees for the differents variables
	degreeHL     int
	degreeHR     int
	degreeHPrime int
}

type indexedProver struct {
	I int
	P SingleThreadedProver
}

// GetClaim returns the sum of all evaluations don't call after folding
func (p *MultiThreadedProver) GetClaim(nCore int) fr.Element {
	// Define usefull constants
	nChunks := len(p.eq)
	evalsChan := make(chan fr.Element, len(p.eq))

	for i := 0; i < nChunks; i++ {
		go p.GetClaimForChunk(i, evalsChan)
	}

	var res fr.Element
	for i := 0; i < nChunks; i++ {
		x := <-evalsChan
		res.Add(&x, &res)
	}

	return res
}

// Prove runs a prover with multi-threading
func (p *MultiThreadedProver) Prove(nCore int) (proof Proof, qPrime, qL, qR, finalClaims []fr.Element) {

	// Define usefull constants
	nChunks := len(p.eq)
	n := nChunks * len(p.eq[0].Table)     // Number of subcircuit. Since we haven't fold on h' yet
	g := nChunks * len(p.vL[0].Table) / n // SubCircuit size. Since we haven't fold on hR yet
	bN := common.Log2Ceil(n)
	bG := common.Log2Ceil(g)
	logNChunk := common.Log2Ceil(nChunks)

	// Initialized the results
	proof.PolyCoeffs = make([][]fr.Element, bN+2*bG)
	qPrime = make([]fr.Element, bN)
	qL = make([]fr.Element, bG)
	qR = make([]fr.Element, bG)
	finalClaims = make([]fr.Element, 3+len(p.staticTables))

	// Initialize the channels
	evalsChan := make(chan []fr.Element, nChunks)
	finChan := make(chan indexedProver, nChunks)
	rChans := make([]chan fr.Element, nChunks)

	// Starts the sub-provers
	for i := 0; i < nChunks; i++ {
		rChans[i] = make(chan fr.Element, 1)
		go p.RunForChunk(i, evalsChan, rChans[i], finChan)
	}

	// Process on all values until all the subprover are completely fold
	for i := 0; i < 2*bG+bN-logNChunk; i++ {
		evals := ConsumeAccumulate(evalsChan, nChunks)
		proof.PolyCoeffs[i] = polynomial.InterpolateOnRange(evals)
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

	newP := ConsumeMergeProvers(finChan, nChunks)

	// Finishes on hPrime. Identical to the single-threaded implementation
	for i := 2*bG + bN - logNChunk; i < bN+2*bG; i++ {
		evals := newP.GetEvalsOnHPrime()
		proof.PolyCoeffs[i] = polynomial.InterpolateOnRange(evals)
		r := common.GetChallenge(proof.PolyCoeffs[i])
		newP.FoldHPrime(r)
		qPrime[i-2*bG] = r
	}

	finalClaims[0] = newP.vL.Table[0]
	finalClaims[1] = newP.vR.Table[0]
	finalClaims[2] = newP.eq.Table[0]
	for i, bkt := range newP.staticTables {
		finalClaims[3+i] = bkt.Table[0]
	}

	close(evalsChan)
	close(finChan)

	return proof, qPrime, qL, qR, finalClaims

}

// ConsumeMergeProvers reallocate the provers from the content of the indexed prover,
// by concatenating their bookkeeping tables.
func ConsumeMergeProvers(ch chan indexedProver, nToMerge int) SingleThreadedProver {

	p := SingleThreadedProver{}

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
	p.gates = indexed.P.gates

	for i := 0; i < nToMerge-1; i++ {
		indexed = <-ch
		newVL[indexed.I] = indexed.P.vL.Table[0]
		newVR[indexed.I] = indexed.P.vR.Table[0]
		newEq[indexed.I] = indexed.P.eq.Table[0]
	}

	p.vL = polynomial.NewBookKeepingTable(newVL)
	p.vR = polynomial.NewBookKeepingTable(newVR)
	p.eq = polynomial.NewBookKeepingTable(newEq)

	return p
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

// GetClaimForChunk runs GetClaim on a chunk, and is aimed at being run in the Background
func (p *MultiThreadedProver) GetClaimForChunk(chunkIndex int, evalsChan chan fr.Element) {
	// Deep-copies the static tables
	staticTablesCopy := make([]polynomial.BookKeepingTable, len(p.staticTables))
	for i := range staticTablesCopy {
		staticTablesCopy[i] = p.staticTables[i].DeepCopy()
	}

	subProver := NewSingleThreadedProver(
		p.vL[chunkIndex],
		p.vR[chunkIndex],
		p.eq[chunkIndex],
		p.gates,
		staticTablesCopy,
	)

	evalsChan <- subProver.GetClaim()
}

// RunForChunk runs thread with a partial prover
func (p *MultiThreadedProver) RunForChunk(
	chunkIndex int,
	evalsChan chan []fr.Element,
	rChan chan fr.Element,
	finChan chan indexedProver,
) {
	// Deep-copies the static tables
	staticTablesCopy := make([]polynomial.BookKeepingTable, len(p.staticTables))
	for i := range staticTablesCopy {
		staticTablesCopy[i] = p.staticTables[i].DeepCopy()
	}

	subProver := NewSingleThreadedProver(
		p.vL[chunkIndex],
		p.vR[chunkIndex],
		p.eq[chunkIndex],
		p.gates,
		staticTablesCopy,
	)

	// Define usefull constants
	n := len(subProver.eq.Table)     // Number of subcircuit. Since we haven't fold on h' yet
	g := len(subProver.vR.Table) / n // SubCircuit size. Since we haven't fold on hR yet
	bN := common.Log2Ceil(n)
	bG := common.Log2Ceil(g)

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
