package sumcheck

import (
	"fmt"

	"github.com/consensys/gkr-mimc/common"
	"github.com/consensys/gkr-mimc/polynomial"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

func Verify(claim fr.Element, proof Proof) (qPrime []fr.Element, finalClaim fr.Element, err error) {
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

		if expectedValue != actualValue {
			return nil, [4]uint64{0, 0, 0, 0}, fmt.Errorf("at round %v verifier eval at 0 + 1 = %v || expected = %v", i, actualValue.String(), expectedValue.String())
		}

		r = common.GetChallenge(proof[i])
		challenges[i] = r
		// expectedValue = P_i(r)
		expectedValue = polynomial.EvaluatePolynomial(proof[i], r)
	}

	return challenges, expectedValue, nil
}
