package gadget

import (
	"fmt"
	"math/big"

	"github.com/AlexandreBelling/gnark/backend/hint"
	"github.com/AlexandreBelling/gnark/frontend"
	"github.com/consensys/gkr-mimc/common"
	gkrNative "github.com/consensys/gkr-mimc/gkr"
	"github.com/consensys/gkr-mimc/hash"
	"github.com/consensys/gkr-mimc/snark/gkr"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"golang.org/x/crypto/sha3"
)

const debug bool = false

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

// NbOutputs of the initial randomness hint
func (h *InitialRandomnessHint) NbOutputs(_ ecc.ID, nbInput int) int {
	return 1
}

// NbOutputs of the gkr prover hint
func (h *GkrProverHint) NbOutputs(_ ecc.ID, nbInput int) int {
	// Find the circuit
	circuit := h.g.Circuit
	// Iteratively finds the bN of the circuit from the input size
	// Can't guarantee that g.ioStore.index contains the right values
	bN := 0

loop:
	for {
		gIn := circuit.InputArity()
		gOut := circuit.OutputArity()
		inputSize := (1<<bN)*(gIn+gOut) +
			bN + common.Log2Ceil(gOut)

		if inputSize == nbInput {
			break loop
		}
		// sanity check in case something must be wrong with the formula
		if inputSize > nbInput {
			panic(fmt.Sprintf("It's too big : %v > %v", inputSize, nbInput))
		}

		bN += 1
	}

	nLayers := len(circuit.Layers)

	nbClaimLeft := nLayers  // claim left
	nbClaimRight := nLayers // claim right

	sumcheckTotalSize := 0
	for i, layer := range circuit.Layers {
		degHL, degHR, degHPrime := layer.Degrees()
		bG := circuit.Layers[i].BGInputs                           // log width of the previous layer's subcircuit
		sumcheckTotalSize += bG*(degHL+degHR+2) + bN*(degHPrime+1) // size of the sumcheck i
	}

	return nbClaimLeft + nbClaimRight + sumcheckTotalSize
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
			// Switch to regular
			res[i].FromMont()
		}
		return res
	}

	// Separate the scalars for the public/private parts
	scalarsPub := subSlice(inpss, h.g.r1cs.pubGkrIo, 0)
	scalarsPriv := subSlice(inpss, h.g.r1cs.privGkrIo, 0)

	// Compute the K associated to the gkr public/private inputs
	var KrsGkr, KrsGkrPriv bn254.G1Affine
	KrsGkr.MultiExp(h.g.r1cs.provingKey.pubKGkr, scalarsPub, ecc.MultiExpConfig{NbTasks: h.g.gkrNCore})
	KrsGkrPriv.MultiExp(h.g.r1cs.provingKey.privKGkrSigma, scalarsPriv, ecc.MultiExpConfig{NbTasks: h.g.gkrNCore})
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

	if debug {
		// For debug : only -> Check that the proof verifies
		verifier := gkrNative.NewVerifier(bN, h.g.Circuit)
		valid := verifier.Verify(gkrProof,
			common.SliceToChunkedSlice(inputs, inputChunkSize),
			common.SliceToChunkedSlice(outputs, outputChunkSize),
			qPrime, q,
		)
		common.Assert(valid, "GKR proof was wrong - Bug in proof generation")
	}

	h.g.gkrProof = &gkrProof

	GkrProofToVec(gkrProof, oups)
	return nil
}

// Writes the proof in a res buffer. We assume the res buffer to be allocated a priori
func GkrProofToVec(proof gkrNative.Proof, resBuff []*big.Int) {
	cursor := 0

	// Writes the sumcheck proofs
	for _, layer := range proof.SumcheckProofs {
		for _, sumcheckRound := range layer.PolyCoeffs {
			for _, val := range sumcheckRound {
				val.ToBigIntRegular(resBuff[cursor])
				cursor += 1
			}
		}
	}

	// Writes the claimLeft
	for _, val := range proof.ClaimsLeft {
		val.ToBigIntRegular(resBuff[cursor])
		cursor += 1
	}

	// Writes the claimRight
	for _, val := range proof.ClaimsRight {
		val.ToBigIntRegular(resBuff[cursor])
		cursor += 1
	}

	// sanity check : expect to have written entirely the vector
	if cursor < len(resBuff) {
		panic("expected to have written the entire buffer")
	}
}

// Reads the proof to obtain the variable equivalent, the gadget is here
// to provide the dimensions
func (g *GkrGadget) GkrProofFromVec(vec []frontend.Variable) gkr.Proof {
	bN := common.Log2Ceil(g.ioStore.index)

	// At this point, all the dimension of the proof are available
	proof := gkr.AllocateProof(bN, g.Circuit)
	cursor := 0

	// Writes the sumcheck proofs
	for i, layer := range proof.SumcheckProofs {
		for j, sumcheckRound := range layer.HPolys {
			for k := range sumcheckRound.Coefficients {
				proof.SumcheckProofs[i].HPolys[j].Coefficients[k] = vec[cursor]
				cursor += 1
			}
		}
	}

	// Writes the claimLeft
	for i := range proof.ClaimsLeft {
		proof.ClaimsLeft[i] = vec[cursor]
		cursor += 1
	}

	// Writes the claimRight
	for i := range proof.ClaimsRight {
		proof.ClaimsRight[i] = vec[cursor]
		cursor += 1
	}

	// sanity check, we expect to have read the entire vector by now
	if cursor < len(vec) {
		panic("the vector was not completely read to complete the proof")
	}

	return proof

}
