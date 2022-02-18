package sumcheck

import (
	"fmt"

	"github.com/consensys/gkr-mimc/circuit"
	"github.com/consensys/gkr-mimc/snark/hash"
	"github.com/consensys/gkr-mimc/snark/polynomial"
	"github.com/consensys/gkr-mimc/sumcheck"

	"github.com/consensys/gnark/frontend"
)

// Proof contains the circuit data of a sumcheck run EXCEPT WHAT IS REQUIRED FOR THE FINAL CHECK.
type Proof []polynomial.Univariate

// AllocateProof allocates an empty sumcheck verifier
func AllocateProof(bN int, gate circuit.Gate) Proof {
	proof := make(Proof, bN)
	for i := 0; i < bN; i++ {
		proof[i] = polynomial.AllocateUnivariate(gate.Degree() + 1)
	}
	return proof
}

// Assign values for the sumcheck verifier
func (p Proof) Assign(proof sumcheck.Proof) {
	if len(proof) != len(p) {
		panic(
			fmt.Sprintf("Inconsistent assignment lenght: expected %v, but got %v", len(p), len(proof)),
		)
	}
	for i, poly := range proof {
		p[i].Assign(poly)
	}
}

// AssertValid verifies a sumcheck instance EXCEPT FOR THE FINAL VERIFICATION.
func (p Proof) AssertValid(cs frontend.API, initialClaim []frontend.Variable) (
	qPrime []frontend.Variable, finalClaim, recombChal frontend.Variable,
) {
	// initialize current claim:
	claimCurr, recombChal := recombineMultiClaims(cs, initialClaim)
	hs := make([]frontend.Variable, len(p))

	for i, pol := range p {
		zeroAndOne := pol.ZeroAndOne(cs)
		cs.AssertIsEqual(zeroAndOne, claimCurr)
		hs[i] = hash.MimcHash(cs, pol...) // Hash the polynomial
		claimCurr = pol.Eval(cs, hs[i])   // Get new current claim
	}

	return hs, claimCurr, recombChal
}

func recombineMultiClaims(cs frontend.API, claims []frontend.Variable) (claim, challenge frontend.Variable) {
	if len(claims) < 1 {
		// No recombination
		return claims[0], nil
	}
	challenge = hash.MimcHash(cs, claims...)
	return polynomial.Univariate(claims).Eval(cs, challenge), challenge
}
