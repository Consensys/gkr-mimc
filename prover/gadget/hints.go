package gadget

import (
	"fmt"
	"math/big"

	"github.com/consensys/gkr-mimc/common"
	gkrNative "github.com/consensys/gkr-mimc/gkr"
	"github.com/consensys/gkr-mimc/hash"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"golang.org/x/crypto/sha3"
)

// Returns the Hint functions that can help gnark's solver figure out that
// the output of the GKR should be a hash
func (g *GkrGadget) HashHint(curve ecc.ID, inps []*big.Int, outputs *big.Int) error {
	var state, block fr.Element
	state.SetBigInt(inps[0])
	block.SetBigInt(inps[1])
	hashed := state

	// Properly computes the hash
	hash.MimcUpdateInplace(&hashed, block)
	hashed.ToBigIntRegular(outputs)
	g.ioStore.index++
	return nil
}

// Derives the initial randomness from an elliptic curve point
func DeriveRandomnessFromPoint(g1 bn254.G1Affine) fr.Element {
	// Hash the uncompressed point, then get a field element out of it
	bytesG1 := g1.RawBytes()
	keccak := sha3.NewLegacyKeccak256()
	keccak.Write(bytesG1[:])
	hashed := keccak.Sum(nil)

	// Derive the initial randomness from the hash
	var randomness fr.Element
	randomness.SetBytes(hashed)
	return randomness
}

// Hint for generating the initial randomness
func (g *GkrGadget) InitialRandomnessHint(_ ecc.ID, inpss []*big.Int, oups *big.Int) error {

	// Takes a subslice and convert to fr.Element
	subSlice := func(array []*big.Int, indices []int, offset int) []fr.Element {
		res := make([]fr.Element, len(indices))
		for i, idx := range indices {
			res[i].SetBigInt(array[idx+offset])
		}
		return res
	}

	// Separate the scalars for the public/private parts
	scalarsPub := subSlice(inpss, g.r1cs.pubGkrIo, 0)
	scalarsPriv := subSlice(inpss, g.r1cs.privGkrIo, 0)

	// Compute the K associated to the gkr public/private inputs
	var KrsGkr bn254.G1Affine
	KrsGkr.MultiExp(g.provingKey.pubKGkr, scalarsPub, ecc.MultiExpConfig{})
	g.proof.KrsGkrPriv.MultiExp(g.provingKey.privKGkrSigma, scalarsPriv, ecc.MultiExpConfig{})

	KrsGkr.Add(&KrsGkr, &g.proof.KrsGkrPriv)

	initialRandomness := DeriveRandomnessFromPoint(KrsGkr)

	initialRandomness.ToBigIntRegular(oups)
	return nil
}

// Returns the Hint functions that can help gnark's solver figure out that
// we need to compute the GkrProof and verify
// In order to return the fields one after the other, the function is built as a stateful iterator
func (g *GkrGadget) GkrProverHint(_ ecc.ID, inputsBI []*big.Int, oups *big.Int) error {

	claims, nLayer, sumRound, coeffIds, inputsBI := inputsBI[0].Uint64(), inputsBI[1].Uint64(),
		inputsBI[2].Uint64(), inputsBI[3].Uint64(), inputsBI[4:]

	if g.gkrProof == nil {

		bN := common.Log2Ceil(g.ioStore.Index())
		paddedIndex := 1 << bN

		nInputs := paddedIndex * g.Circuit.InputArity()
		nOutputs := paddedIndex * g.Circuit.OutputArity()
		bGinitial := common.Log2Ceil(g.Circuit.OutputArity())

		common.Assert(bGinitial == 0, "bGInitial must be zero for Mimc: %v", bGinitial)

		inps := make([]fr.Element, len(inputsBI))
		for i := range inps {
			inps[i].SetBigInt(inputsBI[i])
		}

		inputs, inps := inps[:nInputs], inps[nInputs:]
		// The output: here is passed to force the solver to wait for all the output
		outputs, inps := inps[:nOutputs], inps[nOutputs:]
		qPrime, inps := inps[:bN], inps[bN:]
		q, inps := inps[:bGinitial], inps[bGinitial:]

		inputChunkSize := g.chunkSize * g.Circuit.InputArity()
		outputChunkSize := g.chunkSize * g.Circuit.OutputArity()

		assignment := g.Circuit.Assign(
			common.SliceToChunkedSlice(inputs, inputChunkSize),
			g.gkrNCore,
		)

		prover := gkrNative.NewProver(g.Circuit, assignment)
		gkrProof := prover.Prove(g.gkrNCore, qPrime, q)

		// For debug : only -> Check that the proof verifies
		verifier := gkrNative.NewVerifier(bN, g.Circuit)
		valid := verifier.Verify(gkrProof,
			common.SliceToChunkedSlice(inputs, inputChunkSize),
			common.SliceToChunkedSlice(outputs, outputChunkSize),
			qPrime, q,
		)

		common.Assert(valid, "GKR proof was wrong - Bug in proof generation")
		g.gkrProof = &gkrProof
	}

	var val fr.Element
	switch claims {
	default:
		{
			panic(fmt.Sprintf("claims was %v \n", claims))
		}
	case 0:
		{
			// Not a claim, returns the sumcheck poly
			val = g.gkrProof.SumcheckProofs[nLayer].PolyCoeffs[sumRound][coeffIds]
		}
	case 1:
		{
			// Returns claimLeft
			val = g.gkrProof.ClaimsLeft[nLayer]
		}
	case 2:
		{
			val = g.gkrProof.ClaimsRight[nLayer]
		}
	}

	val.ToBigIntRegular(oups)
	return nil
}
