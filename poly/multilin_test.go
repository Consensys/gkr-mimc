package poly

import (
	"testing"

	"github.com/consensys/gkr-mimc/common"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/stretchr/testify/assert"
)

func TestFold(t *testing.T) {
	// [0, 1, 2, 3]
	bkt := make(MultiLin, 4)
	for i := 0; i < 4; i++ {
		bkt[i].SetUint64(uint64(i))
	}

	var r fr.Element
	r.SetUint64(uint64(5))

	// Folding on 5 should yield [10, 11]
	bkt.Fold(r)

	var ten, eleven fr.Element
	ten.SetUint64(uint64(10))
	eleven.SetUint64(uint64(11))

	assert.Equal(t, ten, bkt[0], "Mismatch on 0")
	assert.Equal(t, eleven, bkt[1], "Mismatch on 1")
}

func TestFoldChunk(t *testing.T) {
	// [0, 1, 2, 3]
	bkt := make(MultiLin, 4)
	for i := 0; i < 4; i++ {
		bkt[i].SetUint64(uint64(i))
	}

	var r fr.Element
	r.SetUint64(uint64(5))

	bktBis := append(MultiLin{}, bkt...)

	// Folding on 5 should yield [10, 11]
	bkt.Fold(r)
	// It should yield the same result
	bktBis.FoldChunk(r, 0, 1)
	bktBis.FoldChunk(r, 1, 2)
	bktBis = bktBis[:2]

	assert.Equal(t, bkt, bktBis)
}

func BenchmarkFolding(b *testing.B) {

	size := 1 << 25

	// [0, 1, 2, 3]
	bkt := make(MultiLin, size)
	for i := 0; i < size; i++ {
		bkt[i].SetUint64(uint64(i))
	}

	var r fr.Element
	r.SetUint64(uint64(5))

	// Folding on 5 should yield [10, 11]

	b.ResetTimer()
	for k := 0; k < b.N; k++ {

		bkt2 := bkt.DeepCopy()
		common.ProfileTrace(b, false, false, func() {
			bkt2.Fold(r)
		})
	}
}
