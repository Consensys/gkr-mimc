package sumcheck2

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

func makeLargeFrSlice(n int) []fr.Element {
	if n > maxNForLargePool {
		panic(fmt.Sprintf("been provided with size of %v but the maximum is %v", n, maxNForLargePool))
	}

	ptr := largeFrSlicePool.Get().(*[]fr.Element)
	return (*ptr)[:n]
}

func dumpInLargePool(arr []fr.Element) {
	largeFrSlicePool.Put(&arr)
}
