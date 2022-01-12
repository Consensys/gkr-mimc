package sumcheck

import (
	"fmt"

	"github.com/consensys/gkr-mimc/snark/hash"
	"github.com/consensys/gkr-mimc/snark/polynomial"
	"github.com/consensys/gkr-mimc/sumcheck"

	"github.com/AlexandreBelling/gnark/frontend"
)

// Proof contains the circuit data of a sumcheck run EXCEPT WHAT IS REQUIRED FOR THE FINAL CHECK.
type Proof struct {
	// bN           int
	// bG           int
	// InitialClaim frontend.Variable
	HPolys []polynomial.Univariate
}

// AllocateProof allocates an empty sumcheck verifier
func AllocateProof(bN, bG, degHL, degHR, degHPrime int) Proof {
	hPolys := make([]polynomial.Univariate, bN+2*bG)
	for i := 0; i < bG; i++ {
		hPolys[i] = polynomial.AllocateUnivariate(degHL)
	}
	for i := bG; i < 2*bG; i++ {
		hPolys[i] = polynomial.AllocateUnivariate(degHR)
	}
	for i := 2 * bG; i < 2*bG+bN; i++ {
		hPolys[i] = polynomial.AllocateUnivariate(degHPrime)
	}

	return Proof{
		HPolys: hPolys,
	}
}

// Assign values for the sumcheck verifier
func (p *Proof) Assign(proof sumcheck.Proof) {
	if len(proof.PolyCoeffs) != len(p.HPolys) {
		panic(
			fmt.Sprintf("Inconsistent assignment lenght: expected %v, but got %v", len(p.HPolys), len(proof.PolyCoeffs)),
		)
	}
	for i, poly := range proof.PolyCoeffs {
		p.HPolys[i].Assign(poly)
	}
}

// AssertValid verifies a sumcheck instance EXCEPT FOR THE FINAL VERIFICATION.
func (p *Proof) AssertValid(cs frontend.API, initialClaim frontend.Variable, bG int) (
	hL, hR, hPrime []frontend.Variable,
	lastClaim frontend.Variable,
) {
	// initialize current claim:
	claimCurr := initialClaim
	hs := make([]frontend.Variable, len(p.HPolys))

	for i, poly := range p.HPolys {
		zeroAndOne := poly.ZeroAndOne(cs)
		cs.AssertIsEqual(zeroAndOne, claimCurr)
		hs[i] = hash.MimcHash(cs, poly.Coefficients...) // Hash the polynomial
		claimCurr = poly.Eval(cs, hs[i])                // Get new current claim
	}

	// A deep-copy to avoid reusing the same underlying slice for all writes
	hL = append([]frontend.Variable{}, hs[:bG]...)
	hR = append([]frontend.Variable{}, hs[bG:2*bG]...)
	hPrime = append([]frontend.Variable{}, hs[2*bG:]...)

	return hL, hR, hPrime, claimCurr
}
