package common

import (
	"fmt"
	"time"
)

type TimeTracker struct {
	label string
	t     time.Time
}

func NewTimer(label string) TimeTracker {
	return TimeTracker{
		label: label,
		t:     time.Now(),
	}
}

func (t TimeTracker) Close() {
	fmt.Printf("Elapsed time for %v : %v (ms) \n", t.label, time.Since(t.t).Milliseconds())
}
