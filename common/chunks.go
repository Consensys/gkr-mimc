package common

// ChunkRange is a container for the beginning and the End of a chunk
type ChunkRange struct {
	Begin, End int
}

// IntoChunkRanges returns a list of range of chunks computed for N entries
// Try to do chunks as big as possible with minChunkSize as a minimum
func IntoChunkRanges(minChunkSize, nCore, chunkPerCore, N int) []ChunkRange {
	chunkSize := Max(minChunkSize, N/(chunkPerCore*nCore))
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
