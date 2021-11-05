package gkr_gadget

import (
	"github.com/consensys/gkr-mimc/circuit"
	"github.com/consensys/gkr-mimc/common"
	gkrNative "github.com/consensys/gkr-mimc/gkr"
	"github.com/consensys/gkr-mimc/hash"
	"github.com/consensys/gkr-mimc/prover/variants/groth16"
	"github.com/consensys/gkr-mimc/snark/gkr"
	"github.com/consensys/gkr-mimc/snark/polynomial"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/backend/hint"
	"github.com/consensys/gnark/frontend"
	"golang.org/x/crypto/sha3"
)

// HINTS ID that we are using for GKR
const GKR_MIMC_GET_HASH_HINT_ID hint.ID = hint.ID(780000001)
const GKR_MIMC_GET_INITIAL_RANDOMNESS_HINT_ID hint.ID = hint.ID(780000002)
const GKR_MIMC_GKR_PROVER_HINT_ID hint.ID = hint.ID(780000003)

var HashOfZeroes fr.Element

func init() {
	var zero fr.Element
	// Since it's the hash of zero, we don't need to the "newState = gkrOutput + block + state" thing
	// We have the equality
	hash.MimcUpdateInplace(&HashOfZeroes, zero)
}

// Helper for performing hashes using GKR
type GkrGadget struct {
	// Pointers to variables that must have been allocated somewhere else
	ioStore           ioStore
	initialRandomness frontend.Variable

	Circuit          circuit.Circuit
	Proof            gkr.Proof
	assignedGkrProof gkrNative.Proof
	provingKey       *groth16.ProvingKey
	proof            groth16.Proof
}

// Pass the update of a hasher to GKR
func (g *GkrGadget) UpdateHasher(
	cs *frontend.ConstraintSystem,
	state frontend.Variable,
	msg frontend.Variable,
) frontend.Variable {
	// Call the hint to get the hash. Since the circuit does not compute the full evaluation
	// of Mimc, we preprocess the inputs to let the circuit work
	left, right := cs.Add(msg, state), state
	output := cs.NewHint(GKR_MIMC_GET_HASH_HINT_ID, left, right)

	g.ioStore.Push([]frontend.Variable{left, right}, []frontend.Variable{output})

	// Since the circuit does not exactly computes the hash,
	// we are left to "finish the computation" by readding the state
	return cs.Add(output, state)
}

// Used for padding dummy values. It adds constants everywhere so the result is not return
// (as it is basically useless)
func (g *GkrGadget) updateHasherWithZeroes(cs *frontend.ConstraintSystem) {
	g.ioStore.Push(
		[]frontend.Variable{cs.Constant(0), cs.Constant(0)},
		[]frontend.Variable{cs.Constant(HashOfZeroes)},
	)
}

// Gadget method to generate the proof
func (g *GkrGadget) GkrProof(cs *frontend.ConstraintSystem, initialRandomness frontend.Variable, bN int) {
	// Expands the initial randomness into q and qPrime
	q := make([]frontend.Variable, 2)
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

	proofInputs := append(g.ioStore.DumpForGkrProver(), append(q, qPrime...)...)

	// Preallocates the proof. It's simpler than recomputing
	// all the dimensions of every slice it contains
	proof := gkr.AllocateProof(bN, g.Circuit)
	for i, sumPi := range proof.SumcheckProofs {
		for j, poly := range sumPi.HPolys {
			for k := range poly.Coefficients {
				// The same hint is going to return everytime a different value
				// The first time it is called, it is going to return all the fields
				proof.SumcheckProofs[i].HPolys[j].Coefficients[k] = cs.NewHint(
					GKR_MIMC_GKR_PROVER_HINT_ID,
					proofInputs,
				)
			}
		}
	}

	// Then finally pull the remaining of the proof from the hint
	for i := range proof.ClaimsLeft {
		proof.ClaimsLeft[i] = cs.NewHint(GKR_MIMC_GKR_PROVER_HINT_ID, proofInputs)
		proof.ClaimsRight[i] = cs.NewHint(GKR_MIMC_GKR_PROVER_HINT_ID, proofInputs)
	}

	proof.AssertValid(
		cs, g.Circuit, q, qPrime,
		polynomial.NewMultilinearByValues(g.ioStore.InputsForVerifier()),
		polynomial.NewMultilinearByValues(g.ioStore.OutputsForVerifier()),
	)

}

// Pad and close GKR, run the proof
func (g *GkrGadget) Close(cs *frontend.ConstraintSystem) {
	bN := common.Log2Ceil(g.ioStore.Index())
	paddedLen := 1 << bN

	// Pad the inputs in order to get a power of two length vector
	for g.ioStore.Index() < paddedLen {
		g.updateHasherWithZeroes(cs)
	}

	// Get the initial randomness
	ios := g.ioStore.DumpForProverMultiExp()
	initialRandomness := cs.NewHint(GKR_MIMC_GET_INITIAL_RANDOMNESS_HINT_ID, ios)
	cs.AssertIsEqual(g.initialRandomness, initialRandomness)

	// Run GKR verifier in the define
	g.GkrProof(cs, initialRandomness, bN)
}

// Returns the Hint functions that can help gnark's solver figure out that
// the output of the GKR should be a hash
func (g *GkrGadget) GenerateComputingHint() hint.Function {
	return hint.Function{
		ID: GKR_MIMC_GET_HASH_HINT_ID,
		F: func(inps []fr.Element) fr.Element {
			state, block := inps[0], inps[1]
			hashed := state

			// Properly computes the hash
			hash.MimcUpdateInplace(&hashed, block)
			return hashed
		},
	}
}

// Hint for generating the initial randomness
func (g *GkrGadget) GenerateInitialRandomnessHint() hint.Function {
	return hint.Function{
		ID: GKR_MIMC_GET_INITIAL_RANDOMNESS_HINT_ID,
		F: func(inps []fr.Element) fr.Element {
			// Compute the KXiBar alongside its proof of computation
			g.proof = groth16.Proof{}
			g.proof.T.MultiExp(g.provingKey.G1.KAlphaXi, inps, ecc.MultiExpConfig{})
			g.proof.KSumXiBar.MultiExp(g.provingKey.G1.KAlphaXi, inps, ecc.MultiExpConfig{})

			// Hash the uncompressed point, then get a field element out of it
			bytesKSumXiBAr := g.proof.KSumXiBar.RawBytes()
			keccak := sha3.NewLegacyKeccak256()
			keccak.Write(bytesKSumXiBAr[:])
			hashed := keccak.Sum(nil)

			// Derive the initial randomness from the hash
			var initialRandomness fr.Element
			initialRandomness.SetBytes(hashed)
			return initialRandomness
		},
	}
}

// Returns the Hint functions that can help gnark's solver figure out that
// we need to compute the GkrProof and verify
// In order to return the fields one after the other, the function is built as a stateful iterator
func (g *GkrGadget) GenerateGkrProverHint(nCore, chunkSize int) hint.Function {

	iterator := NewChainedSlicesIterator()
	iterator.SetCapacity(1024)
	computeProof := true

	// The hint functions throws a go-routine
	return hint.Function{
		ID: GKR_MIMC_GKR_PROVER_HINT_ID,
		F: func(inps []fr.Element) fr.Element {

			if computeProof {
				computeProof = false

				nInputs := g.ioStore.Index() * g.Circuit.InputArity()
				inputs := inps[:nInputs]
				assignment := g.Circuit.Assign(
					common.SliceToChunkedSlice(inputs, chunkSize),
					nCore,
				)

				prover := gkrNative.NewProver(
					g.Circuit,
					assignment,
				)

				gkrProof := prover.Prove(nCore)

				for _, sumPi := range gkrProof.SumcheckProofs {
					iterator.Chain(sumPi.PolyCoeffs...)
				}
			}

			val, finished := iterator.Next()
			if finished {
				panic("The hint was called but all the proof elements were returned")
			}

			return val
		},
	}
}
