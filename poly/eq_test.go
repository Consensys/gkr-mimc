package poly

import (
	"fmt"
	"reflect"
	"testing"

	"github.com/consensys/gkr-mimc/common"
	"github.com/stretchr/testify/assert"
)

func TestGetFoldedEqTable(t *testing.T) {

	for bn := 0; bn < 15; bn++ {
		qPrime := common.RandomFrArray(bn)
		hPrime := common.RandomFrArray(bn)

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
						eq.String(),
						eqBis.String(),
					),
				)
			}
		}
	}
}
