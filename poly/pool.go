package poly

import (
	"fmt"
	"sync"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

// Sets a maximum for the array size we keep in pool
const maxNForLargePool int = 1 << 22
const maxNForSmallPool int = 256

var (
	largePool = sync.Pool{
		New: func() interface{} {
			res := make([]fr.Element, maxNForLargePool)
			return &res
		},
	}
	smallPool = sync.Pool{
		New: func() interface{} {
			res := make([]fr.Element, maxNForSmallPool)
			return &res
		},
	}
)

func MakeLarge(n int) MultiLin {
	if n > maxNForLargePool {
		panic(fmt.Sprintf("been provided with size of %v but the maximum is %v", n, maxNForLargePool))
	}

	ptr := largePool.Get().(*[]fr.Element)
	return (*ptr)[:n]
}

func DumpLarge(arr []fr.Element) {
	// Re-increase the array up to max capacity
	if cap(arr) != maxNForLargePool {
		// If it's capacity does not match, it means it wasn't in the pool
		// in the first place. So just ignore
		return
	}
	largePool.Put(&arr)
}

func MakeSmall(n int) MultiLin {
	if n > maxNForSmallPool {
		panic(fmt.Sprintf("been provided with size of %v but the maximum is %v", n, maxNForSmallPool))
	}

	ptr := smallPool.Get().(*[]fr.Element)
	return (*ptr)[:n]
}

func DumpSmall(arr []fr.Element) {
	// Re-increase the array up to max capacity
	if cap(arr) != maxNForSmallPool {
		// If it's capacity does not match, it means it wasn't in the pool
		// in the first place. So just ignore
		return
	}
	smallPool.Put(&arr)
}
