package gkr

import (
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

	// The initial layer cannot be a multi-instance
	proof.updateWithSumcheck(c, a, nLayers-1)

	for layer := nLayers - 2; layer >= 0; layer-- {

		if len(c[layer].In) < 1 {
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

func (p *Proof) updateWithSumcheck(
	c circuit.Circuit,
	a circuit.Assignment,
	l int,
) {

	// Sumcheck proof
	sumPi, nextQPrime, finalClaims := sumcheck.Prove(
		a.InputLayersOf(c, l),
		p.QPrimes[l],
		p.Claims[l],
		c[l].Gate,
	)

	p.SumcheckProofs[l] = sumPi

	// Then update the qPrimes and Claims for the upcoming sumchecks to use them
	for i := 1; i < len(finalClaims); i++ {
		pos := c[l].In[i-1]
		p.Claims[pos] = append(p.Claims[pos], finalClaims[i])
		p.QPrimes[pos] = append(p.QPrimes[pos], nextQPrime)
	}
}
