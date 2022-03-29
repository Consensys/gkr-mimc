package gkr

import (
	"fmt"
	"sort"

	"github.com/consensys/gkr-mimc/circuit"
	"github.com/consensys/gkr-mimc/sumcheck"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

// Proof contains all the data for a GKR to be verified
type Proof struct {
	SumcheckProofs []sumcheck.Proof
	Claims         [][]fr.Element
	QPrimes        [][][]fr.Element
}

// Prove returns a new prover
func Prove(c circuit.Circuit, a circuit.Assignment, qPrime []fr.Element) (proof Proof) {

	nLayers := len(c)

	// Allocate the proof
	proof.Claims = make([][]fr.Element, nLayers)
	proof.SumcheckProofs = make([]sumcheck.Proof, nLayers)
	proof.QPrimes = make([][][]fr.Element, nLayers)

	// Passes the initial qPrime inside the proof
	proof.QPrimes[nLayers-1] = [][]fr.Element{qPrime}

	for layer := nLayers - 1; layer >= 0; layer-- {

		if c.IsInputLayer(layer) {
			// It's an input layer
			// The proof is complete
			break
		}

		// Otherwise, we are on for a multi-instance with identity
		// The fact this is a multi-identity is specified in the circuit description
		proof.updateWithSumcheck(c, a, layer)
	}

	return
}

func (proof *Proof) updateWithSumcheck(
	c circuit.Circuit,
	a circuit.Assignment,
	layer int,
) {

	// sumcheck proof
	sumPi, nextQPrime, finalClaims := sumcheck.Prove(
		a.InputsOfLayer(c, layer),
		proof.QPrimes[layer],
		proof.Claims[layer],
		c[layer].Gate,
	)

	proof.SumcheckProofs[layer] = sumPi

	// Then update the qPrimes and Claims for the upcoming sumchecks to use them
	for i := 1; i < len(finalClaims); i++ {

		// Index of the corresponding input layer
		inpL := c[layer].In[i-1]

		if len(proof.Claims[inpL]) < 1 {
			// Allocates the entire vectors once, so we can write at any index later
			proof.Claims[inpL] = make([]fr.Element, len(c[inpL].Out))
			proof.QPrimes[inpL] = make([][]fr.Element, len(c[inpL].Out))
		}

		// Seach the position of `l` as an output of layer `inpL`
		// It works because `c[inpL].Out` is guaranteed to be sorted.
		writeAt := sort.SearchInts(c[inpL].Out, layer)

		// Since `SearchInts` does not answer whether the `int` is contained or not
		// but returns the position if it "were" inside. We need to test inclusion
		if c[inpL].Out[writeAt] != layer {
			panic(fmt.Sprintf("circuit misformatted, In and Out are inconsistent between layers %v and %v", layer, inpL))
		}

		proof.Claims[inpL][writeAt] = finalClaims[i]
		proof.QPrimes[inpL][writeAt] = nextQPrime

	}
}
