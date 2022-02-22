package poly

import (
	"fmt"
	"reflect"
	"testing"

	"github.com/consensys/gkr-mimc/common"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/stretchr/testify/assert"
)

func twos(n int) []fr.Element {
	res := make([]fr.Element, n)
	for i := range res {
		res[i] = fr.NewElement(2)
	}
	return res
}

func TestGetFoldedEqTable(t *testing.T) {

	for bn := 3; bn < 10; bn++ {
		qPrime := twos(bn)
		hPrime := twos(bn)

		a := EvalEq(qPrime, hPrime)

		eq := make(MultiLin, 1<<bn)
		FoldedEqTable(eq, qPrime)

		b := eq.Evaluate(hPrime)
		assert.Equal(t, a.String(), b.String(), "bn %v", bn)
	}
}

func TestEqTableChunk(t *testing.T) {

	for bn := 0; bn < 15; bn++ {

		qPrime := common.RandomFrArray(bn)

		eqBis := make(MultiLin, 1<<bn)
		FoldedEqTable(eqBis, qPrime)

		for logChunkSize := 1; logChunkSize < bn; logChunkSize++ {

			eq := make(MultiLin, 1<<bn)
			chunkSize := 1 << logChunkSize
			nChunks := (1 << bn) / chunkSize

			for chunkID := 0; chunkID < nChunks; chunkID++ {
				ChunkOfEqTable(eq, chunkID, chunkSize, qPrime)
			}

			if !reflect.DeepEqual(eq, eqBis) {
				panic(
					fmt.Sprintf(
						"failed at bn = %v and chunksize = %v\n%v\n%v",
						bn, chunkSize,
						common.FrSliceToString(eq),
						common.FrSliceToString(eqBis),
					),
				)
			}
		}
	}

}
