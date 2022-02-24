package poly

import (
	"fmt"
	"reflect"
	"sync"
	"unsafe"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

// Sets a maximum for the array size we keep in pool
const maxNForLargePool int = 1 << 22
const maxNForSmallPool int = 256

// Aliases because it is annoying to use arrays in all the places
type largeArr = [maxNForLargePool]fr.Element
type smallArr = [maxNForSmallPool]fr.Element

var rC sync.Map = sync.Map{}

var (
	largePool = sync.Pool{
		New: func() interface{} {
			var res largeArr
			return &res
		},
	}
	smallPool = sync.Pool{
		New: func() interface{} {
			var res smallArr
			return &res
		},
	}
)

// Clear the pool completely, shields against memory leaks
// Eg: if we forgot to dump a polynomial at some point, this will ensure the value get dumped eventually
// Returns how many polynomials were cleared that way
func ClearPool() int {
	res := 0
	rC.Range(func(k, _ interface{}) bool {
		switch ptr := k.(type) {
		case *largeArr:
			largePool.Put(ptr)
		case *smallArr:
			smallPool.Put(ptr)
		default:
			panic(fmt.Sprintf("tried to clear %v", reflect.TypeOf(ptr)))
		}
		res++
		return true
	})
	return res
}

// Tries to find a reusable MultiLin or allocate a new one
func MakeLarge(n int) MultiLin {
	if n > maxNForLargePool {
		panic(fmt.Sprintf("been provided with size of %v but the maximum is %v", n, maxNForLargePool))
	}

	ptr := largePool.Get().(*largeArr)
	rC.Store(ptr, struct{}{}) // remember we allocated the pointer is being used
	return (*ptr)[:n]
}

// Dumps a set of polynomials into the pool
func DumpLarge(arrs ...MultiLin) {
	for _, arr := range arrs {
		ptr := arr.ptrLarge()
		// If the rC did not registers, then
		// either the array was allocated somewhere else and its fine to ignore
		// otherwise a double put and we MUST ignore
		if _, ok := rC.Load(ptr); ok {
			largePool.Put(ptr)
		}
		// And deregisters the ptr
		rC.Delete(ptr)
	}
}

// Tries to find a reusable MultiLin or allocate a new one
func MakeSmall(n int) MultiLin {
	if n > maxNForSmallPool {
		panic(fmt.Sprintf("want size of %v but the maximum is %v", n, maxNForSmallPool))
	}

	ptr := smallPool.Get().(*smallArr)
	rC.Store(ptr, struct{}{}) // registers the pointer being used
	return (*ptr)[:n]
}

// Dumps a set of polynomials into the pool
func DumpSmall(arrs ...MultiLin) {
	for _, arr := range arrs {
		ptr := arr.ptrSmall()
		// If the rC did not registers, then
		// either the multilin was allocated somewhere else and its fine to ignore
		// otherwise a double put and we MUST ignore
		if _, ok := rC.Load(ptr); ok {
			smallPool.Put(ptr)
		}
		// And deregisters the ptr
		rC.Delete(ptr)
	}
}

// Get the pointer from the header of the slice
func (m MultiLin) ptrLarge() *largeArr {
	// Re-increase the array up to max capacity
	if cap(m) != maxNForLargePool {
		panic(fmt.Sprintf("can't cast to large array, the put array's is %v it should have capacity %v", cap(m), maxNForLargePool))
	}
	return (*largeArr)(unsafe.Pointer(&m[0]))
}

// Get the pointer from the header of the slice
func (m MultiLin) ptrSmall() *smallArr {
	// Re-increase the array up to max capacity
	if cap(m) != maxNForSmallPool {
		panic(fmt.Sprintf("can't cast to small array, the put array's is %v it should have capacity %v", cap(m), maxNForLargePool))
	}
	return (*smallArr)(unsafe.Pointer(&m[0]))
}
