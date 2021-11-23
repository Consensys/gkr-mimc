package gadget

import (
	"github.com/consensys/gkr-mimc/circuit"
	"github.com/consensys/gkr-mimc/common"
	"github.com/consensys/gkr-mimc/examples"
	gkrNative "github.com/consensys/gkr-mimc/gkr"
	"github.com/consensys/gkr-mimc/hash"
	groth16 "github.com/consensys/gkr-mimc/prover/variants"
	"github.com/consensys/gkr-mimc/snark/gkr"
	"github.com/consensys/gkr-mimc/snark/polynomial"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/backend/hint"
	"github.com/consensys/gnark/frontend"
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
	ioStore           IoStore           `gnark:"-"`
	InitialRandomness frontend.Variable `gnark:",public"`

	Circuit   circuit.Circuit `gnark:"-"`
	chunkSize int
	gkrNCore  int

	provingKey groth16.ProvingKey `gnark:"-"`
	proof      groth16.Proof      `gnark:"-"`

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

// Pass the update of a hasher to GKR
func (g *GkrGadget) UpdateHasher(
	cs frontend.API,
	state frontend.Variable,
	msg frontend.Variable,
) frontend.Variable {

	// Call the hint to get the hash. Since the circuit does not compute the full evaluation
	// of Mimc, we preprocess the inputs to let the circuit work
	output := cs.NewHint(g.HashHint, state, msg)

	// Since the circuit does not exactly computes the hash,
	// we are left to "finish the computation" by readding the state
	l := cs.EnforceWire(cs.Add(msg, state))
	r := cs.EnforceWire(state)
	o := cs.EnforceWire(cs.Sub(output, msg, state))

	g.ioStore.PushVarIds(
		[]int{l.WireId(), r.WireId()},
		[]int{o.WireId()},
	)

	g.ioStore.Push(
		[]frontend.Variable{l, r},
		[]frontend.Variable{o},
	)

	return output
}

// Used for padding dummy values. It adds constants everywhere so the result is not return
// (as it is basically useless)
func (g *GkrGadget) updateHasherWithZeroes(cs frontend.API) {
	g.ioStore.Push(
		[]frontend.Variable{cs.Constant(0), cs.Constant(0)},
		[]frontend.Variable{cs.Constant(hashOfZeroes)},
	)
}

func (g *GkrGadget) getInitialRandomness(cs frontend.API) (initialRandomness frontend.Variable, qPrime, q []frontend.Variable) {
	// Get the initial randomness
	ios := g.ioStore.DumpForProverMultiExp()
	bN := common.Log2Ceil(g.ioStore.Index())

	initialRandomness = cs.NewHint(g.InitialRandomnessHint, ios...)

	// Expands the initial randomness into q and qPrime
	q = make([]frontend.Variable, 0)
	qPrime = make([]frontend.Variable, bN)

	tmp := initialRandomness
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
					[]interface{}{cs.Constant(0), cs.Constant(layer), cs.Constant(polyIdx), cs.Constant(coeffIds)},
				)
				proof.SumcheckProofs[layer].
					HPolys[polyIdx].
					Coefficients[coeffIds] = cs.NewHint(g.GkrProverHint, proofInputs...)
			}
		}
	}

	// Then finally pull the remaining of the proof from the hint
	for i := range proof.ClaimsLeft {
		// Set the 4 first entries so that the hint returns the claim lefts
		copy(
			proofInputs[:4],
			[]interface{}{cs.Constant(1), cs.Constant(i), cs.Constant(0), cs.Constant(0)},
		)
		proof.ClaimsLeft[i] = cs.NewHint(g.GkrProverHint, proofInputs...)
		// Returns the claim left but for the same level, only the first entry changes
		proofInputs[0] = cs.Constant(2)
		proof.ClaimsRight[i] = cs.NewHint(g.GkrProverHint, proofInputs...)
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
