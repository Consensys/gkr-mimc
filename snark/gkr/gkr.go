package gkr

import (
	"fmt"
	"sort"

	"github.com/consensys/gkr-mimc/circuit"
	"github.com/consensys/gkr-mimc/gkr"
	poly "github.com/consensys/gkr-mimc/snark/polynomial"
	"github.com/consensys/gkr-mimc/snark/sumcheck"

	"github.com/consensys/gnark/frontend"
)

// Proof represents a GKR proof
// Only valid for the MiMC circuit
type Proof struct {
	SumCheckProofs []sumcheck.Proof
	Claims         [][]frontend.Variable
	QPrimes        [][][]frontend.Variable
}

// AllocateProof allocates a new proof gadget
func AllocateProof(bN int, c circuit.Circuit) (proof Proof) {
	proof.SumCheckProofs = make([]sumcheck.Proof, len(c))
	proof.Claims = make([][]frontend.Variable, len(c))
	proof.QPrimes = make([][][]frontend.Variable, len(c))

	for layer := range c {
		// When the Gate is nil, then it's an input layer
		if c[layer].Gate != nil {
			proof.SumCheckProofs[layer] = sumcheck.AllocateProof(bN, c[layer].Gate)
		}

		// We might also allocate qPrime and the claim for the last layer
		// But remember that they are passed by the user anyway, so they are
		// guaranteed to be allocated prior to
		proof.Claims[layer] = make([]frontend.Variable, len(c[layer].Out))
		proof.QPrimes[layer] = make([][]frontend.Variable, len(c[layer].Out))

		for j := range proof.QPrimes[layer] {
			proof.QPrimes[layer][j] = make([]frontend.Variable, bN)
		}
	}

	// Special case : output layers are , they have no outputs
	// But they need one qPrime and no claims
	proof.Claims[len(proof.Claims)-1] = []frontend.Variable{}
	proof.QPrimes[len(proof.Claims)-1] = [][]frontend.Variable{make([]frontend.Variable, bN)}

	return proof
}

// Assign the proof object
func (proof *Proof) Assign(input gkr.Proof) {
	// sanity-check
	if len(proof.SumCheckProofs) != len(input.SumcheckProofs) {
		panic("not the same number of layers")
	}

	for layer := range input.SumcheckProofs {
		proof.SumCheckProofs[layer].Assign(input.SumcheckProofs[layer])

		if len(input.Claims[layer]) != len(proof.Claims[layer]) {
			panic(fmt.Sprintf(
				"panicked in Assign : at layer %v the gnark input expects %v claims but the assignment contains %v",
				layer, len(proof.Claims[layer]), len(input.Claims[layer]),
			))
		}

		// We might also allocate qPrime and the claim for the last layer
		// But remember that they are passed by the user anyway, so they are
		// guaranteed to be allocated aside from the verification runtime
		for j := range input.Claims[layer] {
			proof.Claims[layer][j] = input.Claims[layer][j]
		}

		for j := range input.QPrimes[layer] {
			for k := range input.QPrimes[layer][j] {
				proof.QPrimes[layer][j][k] = input.QPrimes[layer][j][k]
			}
		}
	}
}

// AssertValid runs the GKR verifier
func (proof *Proof) AssertValid(
	cs frontend.API,
	c circuit.Circuit,
	qPrime []frontend.Variable,
	inputs []poly.MultiLin,
	outputs poly.MultiLin,
) {

	nLayers := len(c)

	for k := range qPrime {
		cs.AssertIsEqual(proof.QPrimes[nLayers-1][0][k], qPrime[k])
	}

	// keep the old vector of claims in a variable, that we can put back in the proof
	// the goal here, is to not modify the proof when calling `Define`
	oldClaim := proof.Claims[nLayers-1]
	// this re-allocates
	proof.Claims[nLayers-1] = append(proof.Claims[nLayers-1], outputs.Eval(cs, qPrime))

	for layer := nLayers - 1; layer >= 0; layer-- {
		if len(c[layer].In) < 1 {
			// It's an input layer
			// No, more sumcheck to verify
			break
		}

		proof.testSumCheck(cs, c, layer)

	}

	for layer := range inputs {
		err := proof.testInitialRound(cs, inputs, layer)
		if err != nil {
			panic(err)
		}
	}

	// re-erase the claim. we added midway to revert the change and keep the proof invariant
	proof.Claims[nLayers-1] = oldClaim

}

func (proof Proof) testSumCheck(cs frontend.API, c circuit.Circuit, layer int) {
	// First thing, test the sumcheck
	nextQprime, nextClaim, recombChal := proof.SumCheckProofs[layer].AssertValid(cs, proof.Claims[layer])
	// 2 is because in practice, a gate cannot have more than two inputs with our designs
	subClaims := make([]frontend.Variable, 0, 2)

	for _, inpL := range c[layer].In {
		// Seach the position of `l` as an output of layer `inpL`
		// It works because `c[inpL].Out` is guaranteed to be sorted.
		readAt := sort.SearchInts(c[inpL].Out, layer)

		// Since `SearchInts` does not answer whether the `int` is contained or not
		// but returns the position if it "were" inside. We need to test inclusion
		if c[inpL].Out[readAt] != layer {
			panic(fmt.Sprintf("circuit misformatted, In and Out are inconsistent between layers %v and %v", layer, inpL))
		}

		for k := range nextQprime {
			cs.AssertIsEqual(proof.QPrimes[inpL][readAt][k], nextQprime[k])
		}

		subClaims = append(subClaims, proof.Claims[inpL][readAt])
	}

	// Run the gate to compute the expected claim
	expectedClaim := c[layer].Gate.GnarkEval(cs, subClaims...)

	// Evaluation of eq to be used for testing the consistency with the challenges
	// Recombines the eq evaluations into a single challenge
	tmpEvals := make(poly.Univariate, len(proof.QPrimes[layer]))
	for i := range proof.QPrimes[layer] {
		tmpEvals[i] = poly.EqEval(cs, proof.QPrimes[layer][i], nextQprime)
	}
	eqEval := tmpEvals.Eval(cs, recombChal)
	expectedClaim = cs.Mul(expectedClaim, eqEval)
	cs.AssertIsEqual(expectedClaim, nextClaim)
}

func (proof Proof) testInitialRound(cs frontend.API, inps []poly.MultiLin, layer int) error {
	actual := inps[layer].Eval(cs, proof.QPrimes[layer][0])
	cs.AssertIsEqual(actual, proof.Claims[layer][0])
	return nil
}
