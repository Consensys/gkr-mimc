package gkr

import (
	"fmt"
	"reflect"
	"sort"

	"github.com/consensys/gkr-mimc/circuit"
	"github.com/consensys/gkr-mimc/common"
	"github.com/consensys/gkr-mimc/poly"
	"github.com/consensys/gkr-mimc/sumcheck"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

func Verify(
	c circuit.Circuit,
	proof Proof,
	inputs []poly.MultiLin,
	outputs poly.MultiLin,
	qPrime []fr.Element,
) (err error) {

	nLayers := len(c)

	if !reflect.DeepEqual(qPrime, proof.QPrimes[nLayers-1][0]) {
		return fmt.Errorf("initial qPrime does not match with the proof %v %v",
			common.FrSliceToString(qPrime),
			common.FrSliceToString(proof.QPrimes[nLayers-1][0]),
		)
	}

	// Pass the initial claim into the proof, because the prover does not compute it
	// For a matter of immutability : the old value of the claim is saved so we can put it
	// back in place before returning
	oldClaim := proof.Claims[nLayers-1]
	proof.Claims[nLayers-1] = append(proof.Claims[nLayers-1], outputs.Evaluate(qPrime))
	defer func() { proof.Claims[nLayers-1] = oldClaim }()

	for layer := nLayers - 1; layer >= 0; layer-- {
		if c.IsInputLayer(layer) {
			// It's an input layer
			// No, more sumcheck to verify
			break
		}

		if err := proof.testSumcheck(c, layer); err != nil {
			return fmt.Errorf("error at layer %v : %v", layer, err)
		}
	}

	for layer := range inputs {
		if err = proof.testInitialRound(inputs, layer); err != nil {
			return err
		}
	}

	return nil

}

func (proof Proof) testSumcheck(
	c circuit.Circuit,
	layer int,
) (err error) {

	// First thing, test the sum-check
	nextQprime, nextClaim, recombChal, err := sumcheck.Verify(
		proof.Claims[layer],
		proof.SumcheckProofs[layer],
	)

	if err != nil {
		return fmt.Errorf("error at sumcheck layer %v %v - claims %v", layer, err, common.FrSliceToString(proof.Claims[layer]))
	}

	var expectedClaim fr.Element
	// 2 is because in practice, a gate cannot have more than two inputs with our designs
	subClaims := make([]*fr.Element, 0, 2)

	for _, inpL := range c[layer].In {

		// Seach the position of `l` as an output of layer `inpL`
		// It works because `c[inpL].Out` is guaranteed to be sorted.
		readAt := sort.SearchInts(c[inpL].Out, layer)

		// Since `SearchInts` does not answer whether the `int` is contained or not
		// but returns the position if it "were" inside. We need to test inclusion
		if c[inpL].Out[readAt] != layer {
			panic(fmt.Sprintf("circuit misformatted, In and Out are inconsistent between layers %v and %v", layer, inpL))
		}

		if !reflect.DeepEqual(proof.QPrimes[inpL][readAt], nextQprime) {
			return fmt.Errorf("mismatch for qPrimes between sumcheck and proof at layer %v", layer)
		}

		subClaims = append(subClaims, &proof.Claims[inpL][readAt])
	}

	// Run the gate to compute the expected claim
	c[layer].Gate.Eval(&expectedClaim, subClaims...)

	// Evaluation of eq to be used for testing the consistency with the challenges
	// Recombines the eq evaluations into a single challenge
	tmpEvals := make([]fr.Element, len(proof.QPrimes[layer]))
	for i := range proof.QPrimes[layer] {
		tmpEvals[i] = poly.EvalEq(proof.QPrimes[layer][i], nextQprime)
	}
	eqEval := poly.EvalUnivariate(tmpEvals, recombChal)

	expectedClaim.Mul(&expectedClaim, &eqEval)

	if expectedClaim != nextClaim {
		return fmt.Errorf("the expected claim and the final claim of the sumcheck do not match for layer %v", layer)
	}

	return nil
}

// Performs one of the GKR checks for the inputs layers
func (proof Proof) testInitialRound(inps []poly.MultiLin, layer int) error {
	qPrime := proof.QPrimes[layer][0]
	claim := proof.Claims[layer][0]
	actual := inps[layer].Evaluate(qPrime)

	if actual != claim {
		return fmt.Errorf(
			"input layer check failed \n\tlayer %v \n\tclaim %v \n\teval %v \n\tqPrime %v",
			layer, claim.String(), actual.String(), common.FrSliceToString(qPrime),
		)
	}
	return nil
}
