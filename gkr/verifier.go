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
	proof.Claims[nLayers-1] = append(proof.Claims[nLayers-1], outputs.Evaluate(qPrime))

	for layer := nLayers - 1; layer >= 0; layer-- {
		if len(c[layer].In) < 1 {
			// It's an input layer
			// No, more sumcheck to verify
			break
		}

		if err := proof.testSumcheck(c, layer); err != nil {
			return err
		}
	}

	for layer := range inputs {
		proof.testInitialRound(inputs, layer)
	}

	return nil

}

func (proof Proof) testSumcheck(
	c circuit.Circuit,
	l int,
) (err error) {

	// First thing, test the sumcheck
	nextQprime, nextClaim, recombChal, err := sumcheck.Verify(
		proof.Claims[l],
		proof.SumcheckProofs[l],
	)

	if err != nil {
		return err
	}

	var expectedClaim fr.Element
	// 2 is because in practice, a gate cannot have more than two inputs with our designs
	subClaims := make([]*fr.Element, 0, 2)

	for _, inpL := range c[l].In {

		// Seach the position of `l` as an output of layer `inpL`
		// It works because `c[inpL].Out` is guaranteed to be sorted.
		readAt := sort.SearchInts(c[inpL].Out, l)

		// Since `SearchInts` does not answer whether the `int` is contained or not
		// but returns the position if it "were" inside. We need to test inclusion
		if c[inpL].Out[readAt] != l {
			panic(fmt.Sprintf("circuit misformatted, In and Out are inconsistent between layers %v and %v", l, inpL))
		}

		if !reflect.DeepEqual(proof.QPrimes[inpL][readAt], nextQprime) {
			return fmt.Errorf("mismatch for qPrimes between sumcheck and proof at layer %v", l)
		}

		subClaims = append(subClaims, &proof.Claims[inpL][readAt])
	}

	// Run the gate to compute the expected claim
	c[l].Gate.Eval(&expectedClaim, subClaims...)

	// Evaluation of eq to be used for testing the consistency with the challenges
	// Recombines the eq evaluations into a single challenge
	tmpEvals := make([]fr.Element, len(proof.QPrimes[l]))
	for i := range proof.QPrimes[l] {
		tmpEvals[i] = poly.EvalEq(proof.QPrimes[l][i], nextQprime)
	}
	eqEval := poly.EvalUnivariate(tmpEvals, recombChal)

	expectedClaim.Mul(&expectedClaim, &eqEval)

	if expectedClaim != nextClaim {
		return fmt.Errorf("the expected claim and the final claim of the sumcheck do not match for layer %v", l)
	}

	return nil
}

func (proof Proof) testInitialRound(inps []poly.MultiLin, layer int) error {
	actual := inps[layer].Evaluate(proof.QPrimes[layer][0])
	if actual == proof.Claims[layer][0] {
		return fmt.Errorf("initial round mismatch")
	}
	return nil
}
