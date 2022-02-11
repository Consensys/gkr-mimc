package poly

import (
	"fmt"
	"sync"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

// Sets a maximum for the array size we keep in pool
const maxNForLargePool int = 1 << 22

var (
	largeFrSlicePool = sync.Pool{
		New: func() interface{} {
			res := make([]fr.Element, maxNForLargePool)
			return &res
		},
	}
)

func MakeLargeFrSlice(n int) MultiLin {
	if n > maxNForLargePool {
		panic(fmt.Sprintf("been provided with size of %v but the maximum is %v", n, maxNForLargePool))
	}

	ptr := largeFrSlicePool.Get().(*[]fr.Element)
	return (*ptr)[:n]
}

func DumpInLargePool(arr []fr.Element) {
	// Re-increase the array up to max capacity
	if cap(arr) < maxNForLargePool {
		// If it's capacity was somehow decreased, we reallocate
		panic("attempted to put a small array in the large pool")
	}
	largeFrSlicePool.Put(&arr)
}
