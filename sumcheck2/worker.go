package sumcheck2

import (
	"runtime"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

type jobType int

// Indicator for the pool to know which action to take
const (
	// Partial evaluation on all variables of a multilinear polynomial except one
	partialEval jobType = iota
	// Folds on a variable
	folding
	// Computes an `eq` table given `q`
	eqTable
)

// A job can be either `folding` or `getPartialEval`
type proverJob struct {
	type_       jobType
	start, stop int
	inst        *instance
	r           fr.Element
	qPrime      []fr.Element
	// This channel is used for both callback folding, or for returning the the partialEval
	callback chan []fr.Element
}

// Closing the jobQueue schedules the end of the pool
var jobQueue chan *proverJob

func init() {
	startWorkerPool()
}

func startWorkerPool() {
	nbWorkers := runtime.NumCPU()
	for i := 0; i < nbWorkers; i++ {
		go func() {
			for job := range jobQueue {
				switch job.type_ {
				case folding:
					runFoldingJob(job)
				case partialEval:
					runPartialEval(job)
				case eqTable:
					runEqTableJob(job)
				}
			}
		}()
	}
}
