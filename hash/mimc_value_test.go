package hash

import (
	"fmt"
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

func TestMimcValue(t *testing.T) {

	var h fr.Element

	// hash single element
	var value1 uint64 = 123
	var state, block fr.Element
	block.SetUint64(value1)
	MimcUpdateInplace(&state, block)
	fmt.Printf("Hash of value1 = %v:\n%v\n", value1, state.String())

	// hash empty slice
	emptySlice := make([]fr.Element, 0)
	h = MimcHash(emptySlice)
	fmt.Printf("Hash of empty slice:\n%v\n", h.String())

	// hash of [123, 1034]
	var value2 uint64 = 1034
	slice := make([]fr.Element, 2)
	slice[0].SetUint64(value1)
	slice[1].SetUint64(value2)
	h = MimcHash(slice)
	fmt.Printf("Hash of [%v, %v]:\n%v\n", value1, value2, h.String())

	// hash of [123, 1034, 546543257896543245]
	var value3 uint64 = 546543257896543245
	var bigFrElement fr.Element
	bigFrElement.SetUint64(value3)
	slice = append(slice, bigFrElement)
	h = MimcHash(slice)
	fmt.Printf("Hash of [%v, %v, %v]:\n%v\n", value1, value2, value3, h.String())
}
