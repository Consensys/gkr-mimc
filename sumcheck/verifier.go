package sumcheck

import (
	"fmt"

	"github.com/consensys/gkr-mimc/common"
	"github.com/consensys/gkr-mimc/poly"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

func Verify(claims []fr.Element, proof Proof) (qPrime []fr.Element, finalClaim, recombChal fr.Element, err error) {
	// Initalize the structures
	bn := len(proof)
	challenges := make([]fr.Element, bn)

	var expectedValue fr.Element
	expectedValue, recombChal = recombineMultiClaims(claims)

	var actualValue, r, zero, one, evalAtOne fr.Element
	one.SetOne()

	for i := 0; i < bn; i++ {
		// Check P_i(0) + P_i(1) == expected
		actualValue = poly.EvalUnivariate(proof[i], zero)
		evalAtOne = poly.EvalUnivariate(proof[i], one)
		actualValue.Add(&actualValue, &evalAtOne)

		if expectedValue != actualValue {
			return nil, fr.Element{}, fr.Element{}, fmt.Errorf("at round %v verifier eval at 0 + 1 = %v || expected = %v", i, actualValue.String(), expectedValue.String())
		}

		r = common.GetChallenge(proof[i])
		challenges[i] = r
		// expectedValue = P_i(r)
		expectedValue = poly.EvalUnivariate(proof[i], r)
	}

	return challenges, expectedValue, recombChal, nil
}

func recombineMultiClaims(claims []fr.Element) (claim, challenge fr.Element) {
	if len(claims) < 1 {
		// No recombination
		return claims[0], fr.Element{}
	}
	challenge = common.GetChallenge(claims)
	return poly.EvalUnivariate(claims, challenge), challenge
}
