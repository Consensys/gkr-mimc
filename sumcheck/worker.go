package sumcheck

import (
	"runtime"
)

// Closing the jobQueue schedules the end of the pool
var jobQueue chan func()

func init() {
	startWorkerPool()
}

func startWorkerPool() {
	// Initialize the jobQueue
	jobQueue = make(chan func(), 8*runtime.NumCPU())

	nbWorkers := runtime.NumCPU()
	for i := 0; i < nbWorkers; i++ {
		go func() {
			for job := range jobQueue {
				job()
			}
		}()
	}
}
