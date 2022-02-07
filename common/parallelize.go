package common

import (
	"runtime"
	"sync"
)

// Parallelize process in parallel the work function
func Parallelize(nbIterations int, work func(int, int), maxCpus ...int) {

	nbTasks := runtime.NumCPU()
	if len(maxCpus) == 1 {
		nbTasks = maxCpus[0]
	}
	nbIterationsPerCpus := nbIterations / nbTasks

	// more CPUs than tasks: a CPU will work on exactly one iteration
	if nbIterationsPerCpus < 1 {
		nbIterationsPerCpus = 1
		nbTasks = nbIterations
	}

	var wg sync.WaitGroup

	extraTasks := nbIterations - (nbTasks * nbIterationsPerCpus)
	extraTasksOffset := 0

	for i := 0; i < nbTasks; i++ {
		wg.Add(1)
		_start := i*nbIterationsPerCpus + extraTasksOffset
		_end := _start + nbIterationsPerCpus
		if extraTasks > 0 {
			_end++
			extraTasks--
			extraTasksOffset++
		}
		go func() {
			work(_start, _end)
			wg.Done()
		}()
	}

	wg.Wait()
}

// Split the large task in smaller chunks appropriately, and `dispatch` for all`.
// Usefull to send jobs to a worker pool, returns `true`.
// If it's not practical to dispatch asynchronously, does nothing and returns `0`
func TryDispatch(nbIteration, minTaskSize int, dispatch func(start, stop int)) int {

	// For better balance between the threads, make small tasks
	nbTasks := runtime.NumCPU() * 8
	nbIterationPerTasks := nbIteration / nbTasks

	if nbIterationPerTasks < minTaskSize {
		// Not enough iterations per tasks to make it worth it parallelizing at max
		// Make bigger tasks
		nbIterationPerTasks = minTaskSize
		nbTasks = nbIteration / nbIterationPerTasks
	}

	if nbTasks <= 1 {
		// Not enough iteration per tasks to make parallelizing interesting at all
		// Does not do anything
		return 0
	}

	// Accounts that `nbTasks` might not divide `nbIteration`
	extraIteration := nbIteration - nbTasks*nbIterationPerTasks
	extraIterationOffset := 0

	for i := 0; i < nbTasks; i++ {
		// Stuffs the extra remain iterations inside the first tasks
		start := i*nbIterationPerTasks + extraIterationOffset
		stop := start + nbIterationPerTasks

		if extraIteration > 0 {
			stop++
			extraIteration--
			extraIterationOffset++
		}

		dispatch(start, stop)
	}

	return nbTasks

}
