package gadget

import (
	"github.com/AlexandreBelling/gnark/backend/hint"
	"github.com/AlexandreBelling/gnark/frontend"
	"github.com/consensys/gkr-mimc/circuit"
	"github.com/consensys/gkr-mimc/common"
	"github.com/consensys/gkr-mimc/examples"
	gkrNative "github.com/consensys/gkr-mimc/gkr"
	"github.com/consensys/gkr-mimc/hash"
	"github.com/consensys/gkr-mimc/snark/gkr"
	"github.com/consensys/gkr-mimc/snark/polynomial"
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

	Circuit   circuit.Circuit `gnark:"-"`
	chunkSize int
	gkrNCore  int

	r1cs  *R1CS  `gnark:"-"`
	proof *Proof `gnark:"-"`

	gkrProof *gkrNative.Proof `gnark:"-"`
}

// NewGkrGadget
func NewGkrGadget() *GkrGadget {
	// Despite the struct having a `Circuit` field, we only allow
	// it to work with the mimc Circuit
	mimc := examples.CreateMimcCircuit()

	return &GkrGadget{
		ioStore:   NewIoStore(&mimc, 16),
		Circuit:   mimc,
		chunkSize: DEFAULT_CHUNK_SIZE,
	}
}

// Used for padding dummy values. It adds constants everywhere so the result is not return
// (as it is basically useless)
func (g *GkrGadget) updateHasherWithZeroes(cs frontend.API) {
	g.ioStore.Push(
		cs,
		[]frontend.Variable{frontend.Variable(0), frontend.Variable(0)},
		[]frontend.Variable{frontend.Variable(hashOfZeroes)},
	)
}

func (g *GkrGadget) getInitialRandomness(cs frontend.API) (initialRandomness frontend.Variable, qPrime, q []frontend.Variable) {
	// Get the initial randomness
	ios := g.ioStore.DumpForProverMultiExp()
	bN := common.Log2Ceil(g.ioStore.Index())

	initialRandomnessArr, err := cs.NewHint(g.InitialRandomnessHint(), ios...)
	initialRandomness = initialRandomnessArr[0]
	common.Assert(err == nil, "Unexpected error %v", err)

	// Expands the initial randomness into q and qPrime
	q = make([]frontend.Variable, 0)
	qPrime = make([]frontend.Variable, bN)

	tmp := initialRandomnessArr[0]
	for i := range q {
		q[i] = tmp
		tmp = cs.Mul(tmp, tmp)
	}

	for i := range qPrime {
		qPrime[i] = tmp
		tmp = cs.Mul(tmp, tmp)
	}

	return initialRandomness, qPrime, q
}

// Runs the Gkr Prover
func (g *GkrGadget) getGkrProof(cs frontend.API, qPrime, q []frontend.Variable) gkr.Proof {

	bN := len(qPrime)
	proofInputs := g.ioStore.DumpForGkrProver(g.chunkSize, qPrime, q)

	// Preallocates the proof. It's simpler than recomputing
	// all the dimensions of every slice it contains
	proof := gkr.AllocateProof(bN, g.Circuit)
	for layer, sumPi := range proof.SumcheckProofs {
		for polyIdx, poly := range sumPi.HPolys {
			for coeffIds := range poly.Coefficients {
				// Set the 4 entries to tell the hint to return a given value of the proof
				copy(
					proofInputs[:4],
					[]frontend.Variable{frontend.Variable(0), frontend.Variable(layer), frontend.Variable(polyIdx), frontend.Variable(coeffIds)},
				)
				newvArr, err := cs.NewHint(g.GkrProverHint(), proofInputs...)
				common.Assert(err == nil, "Unexpected error %v", err)
				proof.SumcheckProofs[layer].HPolys[polyIdx].Coefficients[coeffIds] = newvArr[0]
			}
		}
	}

	// Then finally pull the remaining of the proof from the hint
	for i := range proof.ClaimsLeft {
		// Set the 4 first entries so that the hint returns the claim lefts
		copy(
			proofInputs[:4],
			[]frontend.Variable{frontend.Variable(1), frontend.Variable(i), frontend.Variable(0), frontend.Variable(0)},
		)
		newvArr, err := cs.NewHint(g.GkrProverHint(), proofInputs...)
		common.Assert(err == nil, "Unexpected error %v", err)
		proof.ClaimsLeft[i] = newvArr[0]

		// Returns the claim left but for the same level, only the first entry changes
		proofInputs[0] = frontend.Variable(2)
		newvArr, err = cs.NewHint(g.GkrProverHint(), proofInputs...)
		proof.ClaimsRight[i] = newvArr[0]
		common.Assert(err == nil, "Unexpected error %v", err)
	}

	return proof
}

// Pad and close GKR, run the proof then call the verifier
func (g *GkrGadget) Close(cs frontend.API) {

	bN := common.Log2Ceil(g.ioStore.Index())
	paddedLen := 1 << bN

	// Pad the inputs in order to get a power of two length vector
	for g.ioStore.Index() < paddedLen {
		g.updateHasherWithZeroes(cs)
	}

	// Shrinks the chunkSize so that it does not overflow
	// the number of hashes (after padding)
	if g.chunkSize > paddedLen {
		g.chunkSize = paddedLen
	}

	initialRandomness, qPrime, q := g.getInitialRandomness(cs)

	proof := g.getGkrProof(cs, qPrime, q)

	proof.AssertValid(
		cs, g.Circuit, q, qPrime,
		polynomial.NewMultilinearByValues(g.ioStore.InputsForVerifier(g.chunkSize)),
		polynomial.NewMultilinearByValues(g.ioStore.OutputsForVerifier(g.chunkSize)),
	)

	// The last thing we do is checking that the initialRandomness matches the public one
	cs.AssertIsEqual(g.InitialRandomness, initialRandomness)
}
