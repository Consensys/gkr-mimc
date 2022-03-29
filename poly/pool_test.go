package poly

import "testing"

func TestCountPool(t *testing.T) {
	n := CountPool()
	if n != 0 {
		t.Fatalf("pool should be empty, but it had %v", n)
	}

	MakeSmall(10)

}
