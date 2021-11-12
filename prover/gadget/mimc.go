package gadget

import (
	"github.com/consensys/gkr-mimc/circuit"
	"github.com/consensys/gkr-mimc/common"
	"github.com/consensys/gkr-mimc/examples"
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
	ioStore           IoStore `gnark:"-"`
	InitialRandomness frontend.Variable

	Circuit   circuit.Circuit `gnark:"-"`
	chunkSize int
	gkrNCore  int
	hints     map[hint.ID]hint.Function

	provingKey *groth16.ProvingKey `gnark:"-"`
	proof      groth16.Proof       `gnark:"-"`

	// Internal state of the GetProofHint() closure
	getProofHintState struct {
		gkrProofIterator ChainedSlicesIterator `gnark:"-"`
		computeProof     bool                  `gnark:"-"`
	}
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
	left, right := cs.Add(msg, state), state
	output := cs.NewHint(g.hints[GKR_MIMC_GET_HASH_HINT_ID], left, right)

	g.ioStore.Push([]frontend.Variable{left, right}, []frontend.Variable{output})
	// Since the circuit does not exactly computes the hash,
	// we are left to "finish the computation" by readding the state
	return cs.Add(output, state)
}

// Used for padding dummy values. It adds constants everywhere so the result is not return
// (as it is basically useless)
func (g *GkrGadget) updateHasherWithZeroes(cs frontend.API) {
	g.ioStore.Push(
		[]frontend.Variable{cs.Constant(0), cs.Constant(0)},
		[]frontend.Variable{cs.Constant(hashOfZeroes)},
	)
}

// Gadget method to generate the proof
func (g *GkrGadget) GkrProof(cs frontend.API, initialRandomness frontend.Variable, bN int) {
	// Expands the initial randomness into q and qPrime
	q := make([]frontend.Variable, 0)
	qPrime := make([]frontend.Variable, bN)

	tmp := initialRandomness
	for i := range q {
		q[i] = tmp
		tmp = cs.Mul(tmp, tmp)
	}

	for i := range qPrime {
		qPrime[i] = tmp
		tmp = cs.Mul(tmp, tmp)
	}

	proofInputsVar := append(g.ioStore.DumpForGkrProver(g.chunkSize, qPrime, q), append(q, qPrime...)...)
	proofInputs := VariableToInterfaceSlice(proofInputsVar)

	// Preallocates the proof. It's simpler than recomputing
	// all the dimensions of every slice it contains
	proof := gkr.AllocateProof(bN, g.Circuit)
	for i, sumPi := range proof.SumcheckProofs {
		for j, poly := range sumPi.HPolys {
			for k := range poly.Coefficients {
				// The same hint is going to return everytime a different value
				// The first time it is called, it is going to return all the fields
				proof.SumcheckProofs[i].HPolys[j].Coefficients[k] = cs.NewHint(
					g.hints[GKR_MIMC_GKR_PROVER_HINT_ID],
					proofInputs...,
				)
			}
		}
	}

	// Then finally pull the remaining of the proof from the hint
	for i := range proof.ClaimsLeft {
		proof.ClaimsLeft[i] = cs.NewHint(g.hints[GKR_MIMC_GKR_PROVER_HINT_ID], proofInputs...)
		proof.ClaimsRight[i] = cs.NewHint(g.hints[GKR_MIMC_GKR_PROVER_HINT_ID], proofInputs...)
	}

	proof.AssertValid(
		cs, g.Circuit, q, qPrime,
		polynomial.NewMultilinearByValues(g.ioStore.InputsForVerifier(g.chunkSize)),
		polynomial.NewMultilinearByValues(g.ioStore.OutputsForVerifier(g.chunkSize)),
	)

}

// Pad and close GKR, run the proof
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

	// Get the initial randomness
	ios := g.ioStore.DumpForProverMultiExp()
	initialRandomness := cs.NewHint(g.hints[GKR_MIMC_GET_INITIAL_RANDOMNESS_HINT_ID], VariableToInterfaceSlice(ios)...)
	cs.AssertIsEqual(g.InitialRandomness, initialRandomness)

	// Run GKR verifier in the define
	g.GkrProof(cs, initialRandomness, bN)
}
