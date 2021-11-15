package gadget

import (
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

// Hint for generating the initial randomness
func (g *GkrGadget) InitialRandomnessHint(_ ecc.ID, inpss []*big.Int, oups *big.Int) error {
	scalars := make([]fr.Element, len(inpss))
	for i := range scalars {
		scalars[i].SetBigInt(inpss[i])
	}

	// Compute the KXiBar alongside its proof of computation
	// g.proof = groth16.Proof{}
	// g.proof.T.MultiExp(g.provingKey.G1.KAlphaXi, inps, ecc.MultiExpConfig{})
	var KSumXiBar bn254.G1Affine

	// TODO: Handles the proving key generation
	g.provingKey.G1.KAlphaXi = make([]bn254.G1Affine, len(scalars))

	KSumXiBar.MultiExp(g.provingKey.G1.KAlphaXi, scalars, ecc.MultiExpConfig{})

	// Hash the uncompressed point, then get a field element out of it
	bytesKSumXiBAr := KSumXiBar.RawBytes()
	keccak := sha3.NewLegacyKeccak256()
	keccak.Write(bytesKSumXiBAr[:])
	hashed := keccak.Sum(nil)

	// Derive the initial randomness from the hash
	var initialRandomness fr.Element
	initialRandomness.SetBytes(hashed)

	initialRandomness.ToBigIntRegular(oups)
	return nil
}

// Returns the Hint functions that can help gnark's solver figure out that
// we need to compute the GkrProof and verify
// In order to return the fields one after the other, the function is built as a stateful iterator
func (g *GkrGadget) GkrProverHint(_ ecc.ID, inputsBI []*big.Int, oups *big.Int) error {
	iterator := &g.getProofHintState.gkrProofIterator

	if g.getProofHintState.computeProof {
		g.getProofHintState.computeProof = false

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

		// The proof must be iterated in the order we gather its elements
		// Thus for each layer (in decreasing order), we return the sumcheck proof, the left/right claims
		nLayers := len(gkrProof.SumcheckProofs)
		for layer := nLayers - 1; layer >= 0; layer-- {
			iterator.Chain(gkrProof.SumcheckProofs[layer].PolyCoeffs...)
			// Oddly, the claimRight is read before the claimLeft. The order matters here.
			iterator.Chain([]fr.Element{gkrProof.ClaimsRight[layer], gkrProof.ClaimsLeft[layer]})
		}
	}

	val, finished := iterator.Next()
	if finished {
		panic("The hint was called but all the proof elements were returned")
	}

	val.ToBigIntRegular(oups)
	return nil
}
