package common

import "github.com/consensys/gnark-crypto/ecc/bn254/fr"

// MinChunkSize is the global chunksize used for all multi-threading technics
const MinChunkSize int = 4096

// MaxChunkPerCore is the number of chunks per core we want to use
const MaxChunkPerCore int = 1

// ChunkRange is a container for the beginning and the End of a chunk
type ChunkRange struct {
	Begin, End int
}

// IntoChunkRanges returns a list of range of chunks computed for N entries
// Try to do chunks as big as possible with minChunkSize as a minimum
func IntoChunkRanges(nCore, N int) []ChunkRange {
	chunkSize := Max(MinChunkSize, N/(MaxChunkPerCore*nCore))
	// nChunks is the number of jobs (not necessarily simultaneously) to be run
	nChunks := N / chunkSize
	if nChunks*chunkSize < N {
		// handle the case where n is not divisible by chunkSize
		nChunks++
	}

	chunkRanges := make([]ChunkRange, nChunks)
	Begin := 0
	for i := 0; i < nChunks; i++ {
		chunkRanges[i] = ChunkRange{Begin: Begin, End: Min(N, Begin+chunkSize)}
		Begin += chunkSize
	}

	return chunkRanges
}

// Chunks the slice into multiple slices
// Does not copy nor reallocate the field elements. No reordering occur
func SliceToChunkedSlice(slice []fr.Element, chunkSize int) [][]fr.Element {
	// Sanity check
	if len(slice)%chunkSize > 0 {
		panic("chunkSize should divide the size")
	}

	// Then fills a double slice of fr.Element with the passed slice
	res := make([][]fr.Element, 0, len(slice)/chunkSize)
	for i := 0; i < len(slice); i += chunkSize {
		res = append(res, slice[i:i+chunkSize])
	}

	return res
}
