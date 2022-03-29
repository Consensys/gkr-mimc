package common

import (
	"fmt"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

// FrSliceToString pretty prints a slice of fr.Element to ease debugging
func FrSliceToString(slice []fr.Element) string {
	res := "["
	for _, x := range slice {
		res += fmt.Sprintf("%v, ", x.String())
	}
	res += "]"
	return res
}

// RandomFrArray returns a random array
func RandomFrArray(size int) []fr.Element {
	res := make([]fr.Element, size)
	for i := range res {
		res[i].SetUint64(uint64(i)*uint64(i) ^ 0xf45c9df123f)
	}
	return res
}
