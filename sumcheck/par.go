package sumcheck

import (
	"fmt"
	"sync"

	"github.com/consensys/gkr-mimc/circuit"
	"github.com/consensys/gkr-mimc/common"
	"github.com/consensys/gkr-mimc/polynomial"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

// MultiThreadedProver can process on several threads
type MultiThreadedProver struct {
	// Contains the values of the previous layer
	vL []polynomial.BookKeepingTable
	vR []polynomial.BookKeepingTable
	// Contains the static tables defining the circuit structure
	eq           []polynomial.BookKeepingTable
	gates        []circuit.Gate
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

// NewMultiThreadedProver constructs a new prover
func NewMultiThreadedProver(
	vL []polynomial.BookKeepingTable,
	vR []polynomial.BookKeepingTable,
	eq []polynomial.BookKeepingTable,
	gates []circuit.Gate,
	staticTables []polynomial.BookKeepingTable,
) MultiThreadedProver {
	// Auto-computes the degree on each variables
	degreeHL, degreeHR, degreeHPrime := 0, 0, 0
	for _, gate := range gates {
		dL, dR, dPrime := gate.Degrees()
		degreeHL = common.Max(degreeHL, dL)
		degreeHR = common.Max(degreeHR, dR)
		degreeHPrime = common.Max(degreeHPrime, dPrime)
	}
	return MultiThreadedProver{
		vL:           vL,
		vR:           vR,
		eq:           eq,
		gates:        gates,
		staticTables: staticTables,
		degreeHL:     degreeHL + 1,
		degreeHR:     degreeHR + 1,
		degreeHPrime: degreeHPrime + 1,
	}
}

// GetClaim returns the sum of all evaluations don't call after folding
func (p *MultiThreadedProver) GetClaim(nCore int) fr.Element {
	// Define usefull constants
	nChunks := len(p.eq)
	evalsChan := make(chan fr.Element, len(p.eq))
	semaphore := common.NewSemaphore(nCore)

	for i := 0; i < nChunks; i++ {
		go p.GetClaimForChunk(i, evalsChan, semaphore)
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

	cond := sync.NewCond(&sync.Mutex{})

	// Starts the sub-provers
	for i := 0; i < nCore; i++ {
		maxChunksize := nChunks / nCore
		chunkStart := i * maxChunksize
		chunkStop := common.Min(chunkStart+maxChunksize, nChunks)
		go p.RunForChunks(chunkStart, chunkStop, cond, evalsChan, qL, qR, qPrime, finChan)
	}

	// Process on all values until all the subprover are completely fold
	for i := 0; i < 2*bG+bN-logNChunk; i++ {
		evals := ConsumeAccumulate(evalsChan, nCore)
		proof.PolyCoeffs[i] = polynomial.InterpolateOnRange(evals)
		r := common.GetChallenge(proof.PolyCoeffs[i])
		if i < bG {
			qL[i] = r
		} else if i < 2*bG {
			qR[i-bG] = r
		} else {
			qPrime[i-2*bG] = r
		}

		cond.L.Lock()
		cond.Broadcast()
		cond.L.Unlock()

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
	staticTables := indexed.P.staticTables
	gates := indexed.P.gates

	for i := 0; i < nToMerge-1; i++ {
		indexed = <-ch
		fmt.Printf("Got number %v \n", indexed.I)
		newVL[indexed.I] = indexed.P.vL.Table[0]
		newVR[indexed.I] = indexed.P.vR.Table[0]
		newEq[indexed.I] = indexed.P.eq.Table[0]
	}

	return NewSingleThreadedProver(
		polynomial.NewBookKeepingTable(newVL),
		polynomial.NewBookKeepingTable(newVR),
		polynomial.NewBookKeepingTable(newEq),
		gates,
		staticTables,
	)
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
	var wg sync.WaitGroup
	wg.Add(len(chs))
	for _, ch := range chs {
		go func(ch chan fr.Element) {
			ch <- r
			wg.Done()
		}(ch)
	}
	wg.Wait()
}

// GetClaimForChunk runs GetClaim on a chunk, and is aimed at being run in the Background
func (p *MultiThreadedProver) GetClaimForChunk(chunkIndex int, evalsChan chan fr.Element, semaphore common.Semaphore) {
	semaphore.Acquire()
	defer semaphore.Release()

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

// Runs for a sequence of chunks
// Lighter on synchronization variables
func (p *MultiThreadedProver) RunForChunks(
	chunkStart int,
	chunkStop int,
	cond *sync.Cond,
	evalsChan chan []fr.Element,
	qL, qR, qPrime []fr.Element,
	finChan chan indexedProver,
) {

	subProvers := make([]SingleThreadedProver, chunkStop-chunkStart)
	for chunkIndex := chunkStart; chunkIndex < chunkStop; chunkIndex++ {

		// Deep-copies the static tables
		staticTablesCopy := make([]polynomial.BookKeepingTable, len(p.staticTables))
		for i := range staticTablesCopy {
			staticTablesCopy[i] = p.staticTables[i].DeepCopy()
		}

		subProvers[chunkIndex-chunkStart] = NewSingleThreadedProver(
			p.vL[chunkIndex],
			p.vR[chunkIndex],
			p.eq[chunkIndex],
			p.gates,
			staticTablesCopy,
		)
	}

	// Define usefull constants
	n := len(subProvers[0].eq.Table)     // Number of subcircuit. Since we haven't fold on h' yet
	g := len(subProvers[0].vR.Table) / n // SubCircuit size. Since we haven't fold on hR yet
	bN := common.Log2Ceil(n)
	bG := common.Log2Ceil(g)

	// Run on hL
	for i := 0; i < bG; i++ {

		evalHL := subProvers[0].GetEvalsOnHL()
		for chunkIndex := 1; chunkIndex < chunkStop-chunkStart; chunkIndex++ {
			eval := subProvers[chunkIndex].GetEvalsOnHL()
			for k := range eval {
				evalHL[k].Add(&evalHL[k], &eval[k])
			}
		}
		// Sends on the main thread
		evalsChan <- evalHL
		// And spinlock to save the overheads of broadcasting
		r := WaitForIt(cond, &qL[i])
		for chunkIndex := range subProvers {
			subProvers[chunkIndex].FoldHL(r)
		}
	}

	// Run on hR
	for i := 0; i < bG; i++ {

		evalHR := subProvers[0].GetEvalsOnHR()
		for chunkIndex := 1; chunkIndex < chunkStop-chunkStart; chunkIndex++ {
			eval := subProvers[chunkIndex].GetEvalsOnHR()
			for k := range eval {
				evalHR[k].Add(&evalHR[k], &eval[k])
			}
		}
		evalsChan <- evalHR
		r := WaitForIt(cond, &qR[i])
		for chunkIndex := range subProvers {
			subProvers[chunkIndex].FoldHR(r)
		}
	}

	// Run on hPrime
	for i := 0; i < bN; i++ {
		evalHPrime := subProvers[0].GetEvalsOnHPrime()
		for chunkIndex := 1; chunkIndex < chunkStop-chunkStart; chunkIndex++ {
			eval := subProvers[chunkIndex].GetEvalsOnHPrime()
			for k := range eval {
				evalHPrime[k].Add(&evalHPrime[k], &eval[k])
			}
		}
		// Sends on the main thread
		evalsChan <- evalHPrime
		r := WaitForIt(cond, &qPrime[i])
		for chunkIndex := range subProvers {
			subProvers[chunkIndex].FoldHPrime(r)
		}
	}

	for chunkIndex := range subProvers {
		finChan <- indexedProver{I: chunkIndex + chunkStart, P: subProvers[chunkIndex]}
	}
}

func WaitForIt(cond *sync.Cond, rsc *fr.Element) fr.Element {
	// this go routine wait for changes to the sharedRsc
	cond.L.Lock()
	for rsc.IsZero() {
		cond.Wait()
	}
	cond.L.Unlock()
	return *rsc
}
