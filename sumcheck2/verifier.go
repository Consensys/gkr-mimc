package sumcheck2

import (
	"fmt"

	"github.com/consensys/gkr-mimc/common"
	"github.com/consensys/gkr-mimc/polynomial"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

func Verify(claim fr.Element, proof Proof) (valid bool, qPrime []fr.Element, finalClaim fr.Element) {
	// Initalize the structures
	bn := len(proof)
	challenges := make([]fr.Element, bn)
	var expectedValue fr.Element = claim
	var actualValue, r, zero, one, evalAtOne fr.Element
	one.SetOne()

	for i := 0; i < bn; i++ {
		// Check P_i(0) + P_i(1) == expected
		actualValue = polynomial.EvaluatePolynomial(proof[i], zero)
		evalAtOne = polynomial.EvaluatePolynomial(proof[i], one)
		actualValue.Add(&actualValue, &evalAtOne)

		fmt.Printf("verifier eval at 0 + 1 = %v || expected = %v\n", actualValue.String(), expectedValue.String())

		if expectedValue != actualValue {
			return false, nil, [4]uint64{0, 0, 0, 0}
		}

		// expectedValue = P_i(r)
		r = common.GetChallenge(proof[i])
		challenges[i] = r
		expectedValue = polynomial.EvaluatePolynomial(proof[i], r)
	}

	return true, challenges, expectedValue
}
