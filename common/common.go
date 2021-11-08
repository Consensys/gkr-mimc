package common

import (
	"fmt"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

// PrettyStringFr returns Fr in a nice way (like showing negative numbers in an elegant way)
func PrettyStringFr(x fr.Element) string {
	negX := x
	negX.Neg(&negX)
	negXStr := negX.String()
	xStr := x.String()

	if len(xStr) <= len(negXStr) {
		return xStr
	}

	return fmt.Sprintf("-%v", negXStr)
}

// FrSliceToString pretty prints a slice of fr.Element to ease debugging
func FrSliceToString(slice []fr.Element) string {
	res := "["
	for _, x := range slice {
		res += fmt.Sprintf("%v, ", PrettyStringFr(x))
	}
	res += "]"
	return res
}

// UintSliceToString pretty-prints a slice of uint for debugging
func UintSliceToString(slice []uint) string {
	res := "["
	for _, x := range slice {
		res += fmt.Sprintf("%v, ", x)
	}
	res += "]"
	return res
}

// IntSliceToString pretty-prints a slice of int for debugging
func IntSliceToString(slice []int) string {
	res := "["
	for _, x := range slice {
		res += fmt.Sprintf("%v, ", x)
	}
	res += "]"
	return res
}

// FrToGenericArray downcast to an slice of interface
func FrToGenericArray(slice []fr.Element) []interface{} {
	res := make([]interface{}, len(slice))
	for i := range slice {
		res[i] = slice[i]
	}
	return res
}

// RandomFrArray returns a random array
func RandomFrArray(size int) []fr.Element {
	res := make([]fr.Element, size)
	for i := range res {
		res[i].SetRandom()
	}
	return res
}

// RandomFrDoubleSlice returns a random double slice of fr.Element
func RandomFrDoubleSlice(nChunks, chunkSize int) [][]fr.Element {
	res := make([][]fr.Element, nChunks)
	for i := range res {
		res[i] = make([]fr.Element, chunkSize)
		for j := range res[i] {
			res[i][j].SetRandom()
		}
	}
	return res
}

// Uint64ToFr allows to quickly create fr.Element
func Uint64ToFr(x uint64) fr.Element {
	var res fr.Element
	res.SetUint64(x)
	return res
}

// Assert is equivalent of if
// ```
// if !assertion {
//		panic(fmt.Sprintf(msg, args...))
//}
// ```
func Assert(assertion bool, msg string, args ...interface{}) {
	if !assertion {
		panic(fmt.Sprintf(msg, args...))
	}
}
