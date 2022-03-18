package gadget

import (
	"github.com/AlexandreBelling/gnark/backend/hint"
	"github.com/AlexandreBelling/gnark/frontend"
	"github.com/consensys/gkr-mimc/circuit"
	"github.com/consensys/gkr-mimc/common"
	"github.com/consensys/gkr-mimc/examples"
	"github.com/consensys/gkr-mimc/hash"
	"github.com/consensys/gkr-mimc/snark/gkr"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

// HINTS ID that we are using for GKR
const GKR_MIMC_GET_HASH_HINT_ID hint.ID = hint.ID(780000001)
const GKR_MIMC_GET_INITIAL_RANDOMNESS_HINT_ID hint.ID = hint.ID(780000002)
const GKR_MIMC_GKR_PROVER_HINT_ID hint.ID = hint.ID(780000003)

// Caches the result of the `UpdateMimcHash(0, 0)`
// For padding
var hashOfZeroes fr.Element

// Default chunkSize used by GKR
const DEFAULT_CHUNK_SIZE int = 1024

func init() {
	var zero fr.Element
	// Since it's the hash of zero, we don't need to the "newState = gkrOutput + block + state" thing
	// We have the equality
	hash.MimcUpdateInplace(&hashOfZeroes, zero)
}

// Helper for performing hashes using GKR
type GkrGadget struct {
	// Pointers to variables that must have been allocated somewhere else
	InitialRandomness frontend.Variable `gnark:",public"`
	ioStore           IoStore           `gnark:"-"`

	Circuit circuit.Circuit `gnark:"-"`

	r1cs  *R1CS  `gnark:"-"`
	proof *Proof `gnark:"-"`
}

// NewGkrGadget
func NewGkrGadget() *GkrGadget {
	// Despite the struct having a `Circuit` field, we only allow
	// it to work with the mimc Circuit
	mimc := examples.MimcCircuit()

	return &GkrGadget{
		ioStore: NewIoStore(&mimc, 16),
		Circuit: mimc,
	}
}

// Used for padding dummy values. It adds constants everywhere so the result is not return
// (as it is basically useless)
func (g *GkrGadget) updateHasherWithZeroes(cs frontend.API) {
	g.ioStore.Push(
		cs,
		[]frontend.Variable{frontend.Variable(0), frontend.Variable(0)},
		hashOfZeroes,
	)
}

func (g *GkrGadget) getInitialRandomness(cs frontend.API) (initialRandomness frontend.Variable, qPrime []frontend.Variable) {
	// Get the initial randomness
	ios := g.ioStore.DumpForProverMultiExp()
	bN := common.Log2Ceil(g.ioStore.Index())

	initialRandomnessArr, err := cs.NewHint(g.InitialRandomnessHint(), ios...)
	initialRandomness = initialRandomnessArr[0]
	common.Assert(err == nil, "Unexpected error %v", err)

	// Expands the initial randomness into q and qPrime
	qPrime = make([]frontend.Variable, bN)
	tmp := initialRandomnessArr[0]

	for i := range qPrime {
		qPrime[i] = tmp
		tmp = cs.Mul(tmp, tmp)
	}

	return initialRandomness, qPrime
}

// Runs the Gkr Prover
func (g *GkrGadget) getGkrProof(cs frontend.API, qPrime []frontend.Variable) gkr.Proof {

	proofInputs := g.ioStore.DumpForGkrProver(qPrime)
	proofVec, err := cs.NewHint(g.GkrProverHint(), proofInputs...)

	common.Assert(err == nil, "unexpected error in the gkr prover hint %v", err)
	if err != nil {
		panic("unexpected error in the gkr prover hint")
	}

	return g.GkrProofFromVec(proofVec)
}

// Pad and close GKR, run the proof then call the verifier
func (g *GkrGadget) Close(cs frontend.API) {

	bN := common.Log2Ceil(g.ioStore.Index())
	paddedLen := 1 << bN

	// Pad the inputs in order to get a power of two length vector
	for g.ioStore.Index() < paddedLen {
		g.updateHasherWithZeroes(cs)
	}

	initialRandomness, qPrime := g.getInitialRandomness(cs)
	proof := g.getGkrProof(cs, qPrime)
	proof.AssertValid(cs, g.Circuit, qPrime, g.ioStore.InputsForVerifier(), g.ioStore.OutputsForVerifier())

	// The last thing we do is checking that the initialRandomness matches the public one
	cs.AssertIsEqual(g.InitialRandomness, initialRandomness)
}
