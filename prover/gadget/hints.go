package gadget

const 

import (
	"fmt"
	"math/big"

	"github.com/AlexandreBelling/gnark/backend/hint"
	"github.com/consensys/gkr-mimc/common"
	gkrNative "github.com/consensys/gkr-mimc/gkr"
	"github.com/consensys/gkr-mimc/hash"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"golang.org/x/crypto/sha3"
)

type HashHint struct {
	g *GkrGadget
}

type InitialRandomnessHint struct {
	g *GkrGadget
}

type GkrProverHint struct {
	g *GkrGadget
}

// Accessor for the hint from the GkrGadget
func (g *GkrGadget) HashHint() *HashHint {
	return &HashHint{g: g}
}

// Accessor for the hint from the InitialRandomnessHint
func (g *GkrGadget) InitialRandomnessHint() *InitialRandomnessHint {
	return &InitialRandomnessHint{g: g}
}

// Accessor for the hint from the GkrProver
func (g *GkrGadget) GkrProverHint() *GkrProverHint {
	return &GkrProverHint{g: g}
}

// UUID of the hash hint
func (h *HashHint) UUID() hint.ID {
	return 156461454
}

// UUID of the initial randomness hint hint
func (h *InitialRandomnessHint) UUID() hint.ID {
	return 46842135
}

// UUID of the gkr prover hint hint
func (h *GkrProverHint) UUID() hint.ID {
	return 13135755
}

// NbOutputs of the hash hint
func (h *HashHint) NbOutputs(_ ecc.ID, nbInput int) int {
	return 1
}

// NbOutputs of the initial randomness hint hint
func (h *InitialRandomnessHint) NbOutputs(_ ecc.ID, nbInput int) int {
	return 1
}

// NbOutputs of the gkr prover hint hint
func (h *GkrProverHint) NbOutputs(_ ecc.ID, nbInput int) int {
	return 1
}

// String of the hash hint
func (h *HashHint) String() string {
	return "HashHint"
}

// String of the initial randomness hint hint
func (h *InitialRandomnessHint) String() string {
	return "InitialRandomnessHint"
}

// String of the gkr prover hint hint
func (h *GkrProverHint) String() string {
	return "GkrProverHint"
}

// Returns the Hint functions that can help gnark's solver figure out that
// the output of the GKR should be a hash
func (h *HashHint) Call(curve ecc.ID, inps []*big.Int, outputs []*big.Int) error {
	var state, block fr.Element
	state.SetBigInt(inps[0])
	block.SetBigInt(inps[1])
	hashed := state

	// Properly computes the hash
	hash.MimcUpdateInplace(&hashed, block)
	hashed.ToBigIntRegular(outputs[0])
	h.g.ioStore.index++
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
func (h *InitialRandomnessHint) Call(_ ecc.ID, inpss []*big.Int, oups []*big.Int) error {

	// Takes a subslice and convert to fr.Element
	subSlice := func(array []*big.Int, indices []int, offset int) []fr.Element {
		res := make([]fr.Element, len(indices))
		for i, idx := range indices {
			res[i].SetBigInt(array[idx+offset])
			// Switch to MontGommery
			res[i].FromMont()
		}
		return res
	}

	// Separate the scalars for the public/private parts
	scalarsPub := subSlice(inpss, h.g.r1cs.pubGkrIo, 0)
	scalarsPriv := subSlice(inpss, h.g.r1cs.privGkrIo, 0)

	// Compute the K associated to the gkr public/private inputs
	var KrsGkr, KrsGkrPriv bn254.G1Affine
	KrsGkr.MultiExp(h.g.r1cs.provingKey.pubKGkr, scalarsPub, ecc.MultiexpConfig{NbTasks: runtime.NumCPU()})
	KrsGkrPriv.MultiExp(h.g.r1cs.provingKey.privKGkrSigma, scalarsPriv, ecc.MultiexpConfig{NbTasks: runtime.NumCPU()})
	KrsGkr.Add(&KrsGkr, &KrsGkrPriv)

	h.g.proof = &Proof{KrsGkrPriv: KrsGkrPriv}

	initialRandomness := DeriveRandomnessFromPoint(KrsGkr)
	initialRandomness.ToBigIntRegular(oups[0])

	return nil
}

// Returns the Hint functions that can help gnark's solver figure out that
// we need to compute the GkrProof and verify
// In order to return the fields one after the other, the function is built as a stateful iterator
func (h *GkrProverHint) Call(_ ecc.ID, inputsBI []*big.Int, oups []*big.Int) error {

	claims, nLayer, sumRound, coeffIds, inputsBI := inputsBI[0].Uint64(), inputsBI[1].Uint64(),
		inputsBI[2].Uint64(), inputsBI[3].Uint64(), inputsBI[4:]

	if h.g.gkrProof == nil {

		bN := common.Log2Ceil(h.g.ioStore.Index())
		paddedIndex := 1 << bN
		h.g.chunkSize = common.Min(h.g.chunkSize, paddedIndex)

		nInputs := paddedIndex * h.g.Circuit.InputArity()
		nOutputs := paddedIndex * h.g.Circuit.OutputArity()
		bGinitial := common.Log2Ceil(h.g.Circuit.OutputArity())

		common.Assert(bGinitial == 0, "bGInitial must be zero for Mimc: %v", bGinitial)

		inps := make([]fr.Element, len(inputsBI))
		for i := range inps {
			inps[i].SetBigInt(inputsBI[i])
		}

		inputs, inps := inps[:nInputs], inps[nInputs:]
		// The output: here is passed to force the solver to wait for all the output
		outputs, inps := inps[:nOutputs], inps[nOutputs:]
		qPrime, inps := inps[:bN], inps[bN:]
		q, _ := inps[:bGinitial], inps[bGinitial:]

		inputChunkSize := h.g.chunkSize * h.g.Circuit.InputArity()
		outputChunkSize := h.g.chunkSize * h.g.Circuit.OutputArity()

		assignment := h.g.Circuit.Assign(
			common.SliceToChunkedSlice(inputs, inputChunkSize),
			h.g.gkrNCore,
		)

		prover := gkrNative.NewProver(h.g.Circuit, assignment)
		gkrProof := prover.Prove(h.g.gkrNCore, qPrime, q)

		// For debug : only -> Check that the proof verifies
		verifier := gkrNative.NewVerifier(bN, h.g.Circuit)
		valid := verifier.Verify(gkrProof,
			common.SliceToChunkedSlice(inputs, inputChunkSize),
			common.SliceToChunkedSlice(outputs, outputChunkSize),
			qPrime, q,
		)

		common.Assert(valid, "GKR proof was wrong - Bug in proof generation")
		h.g.gkrProof = &gkrProof
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
			val = h.g.gkrProof.SumcheckProofs[nLayer].PolyCoeffs[sumRound][coeffIds]
		}
	case 1:
		{
			// Returns claimLeft
			val = h.g.gkrProof.ClaimsLeft[nLayer]
		}
	case 2:
		{
			val = h.g.gkrProof.ClaimsRight[nLayer]
		}
	}

	val.ToBigIntRegular(oups[0])
	return nil
}
