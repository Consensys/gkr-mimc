package gkr

import (
	"gkr-mimc/common"
	"gkr-mimc/sumcheck"

	"github.com/consensys/gurvy/bn256/fr"
)

// Prover contains all relevant data for a GKR prover
type Prover struct {
	bN         int
	circuit    Circuit
	assignment Assignment
}

// Proof contains all the data for a GKR to be verified
type Proof struct {
	SumcheckProofs []sumcheck.Proof
	ClaimsLeft     []fr.Element
	ClaimsRight    []fr.Element
}

// NewProver returns a new prover
func NewProver(circuit Circuit, assignment Assignment) Prover {
	bN := common.Log2(len(assignment.values[0])) - circuit.bGs[0]
	return Prover{
		bN:         bN,
		circuit:    circuit,
		assignment: assignment,
	}
}

// GetInitialQPrimeAndQ returns the initial randomness of the protocol
func GetInitialQPrimeAndQ(bN, bG int) ([]fr.Element, []fr.Element) {
	q := make([]fr.Element, bG)
	qPrime := make([]fr.Element, bN)

	// actually compute qInitial and qPrimeInitial
	// TODO: Uses actual randomness
	for i := range q {
		q[i].SetUint64(uint64(i + 1))
	}

	for i := range qPrime {
		qPrime[i].SetUint64(uint64(i + 1))
	}

	return qPrime, q
}

// GetBookKeepingTablesForInitialRound generates and prefold the book-keeping tables for a the initial GKR round
func (p *Prover) GetBookKeepingTablesForInitialRound(
	qPrime, q []fr.Element,
) (
	vL, vR, eq sumcheck.BookKeepingTable,
	statics []sumcheck.BookKeepingTable,
) {
	// For the initial round, we always take the last layer
	layer := len(p.circuit.gates) - 1
	// In the Mimc use-case, the static table contains [cipher, copy].
	// Those are the static table, because they do not depends on the assignment
	staticTableGens := p.circuit.staticTableGens[layer]
	// The +2 is because of vL and vR. They are stored in the first two slots.
	statics = make([]sumcheck.BookKeepingTable, len(staticTableGens))
	// First vL
	vL = p.assignment.LayerAsBKTWithCopy(layer)
	vR = p.assignment.LayerAsBKTWithCopy(layer)
	eq = sumcheck.PrefoldedEqTable(qPrime)
	// Then the staticTables in the order given by
	for i, gen := range staticTableGens {
		statics[i] = gen(q)
	}
	return vL, vR, eq, statics
}

// GetBookKeepingTablesForIntermediateRound generates and prefold the book-keeping tables for an intermediate round
func (p *Prover) GetBookKeepingTablesForIntermediateRound(
	layer int,
	qPrime, qL, qR []fr.Element,
	lambdaL, lambdaR fr.Element,
) (
	vL, vR, eq sumcheck.BookKeepingTable,
	statics []sumcheck.BookKeepingTable,
) {
	// In the Mimc use-case, the static table contains [cipher, copy].
	// Those are the static table, because they do not depends on the assignment
	staticTableGens := p.circuit.staticTableGens[layer]
	// The +2 is because of vL and vR. They are stored in the first two slots.
	statics = make([]sumcheck.BookKeepingTable, len(staticTableGens))
	// First vL
	vL = p.assignment.LayerAsBKTWithCopy(layer)
	vR = p.assignment.LayerAsBKTWithCopy(layer)
	eq = sumcheck.PrefoldedEqTable(qPrime)
	// Then the staticTables in the order given by
	for i, gen := range staticTableGens {
		bkL := gen(qL)
		bkR := gen(qR)
		statics[i] = sumcheck.LinearCombinationOfBookKeepingTables(bkL, bkR, lambdaL, lambdaR)
	}

	return vL, vR, eq, statics
}

// InitialRoundSumcheckProver returns a prover object for the initial round
func (p *Prover) InitialRoundSumcheckProver(qPrime []fr.Element, q []fr.Element) sumcheck.Prover {
	layer := len(p.circuit.gates) - 1
	vL, vR, eq, statics := p.GetBookKeepingTablesForInitialRound(qPrime, q)
	return sumcheck.NewProver(vL, vR, eq, p.circuit.gates[layer], statics)
}

// IntermediateRoundsSumcheckProver returns a prover object for the intermediate round
func (p *Prover) IntermediateRoundsSumcheckProver(
	layer int,
	qPrime, qL, qR []fr.Element,
	lambdaL, lambdaR fr.Element,
) sumcheck.Prover {
	vL, vR, eq, statics := p.GetBookKeepingTablesForIntermediateRound(layer, qPrime, qL, qR, lambdaL, lambdaR)
	return sumcheck.NewProver(vL, vR, eq, p.circuit.gates[layer], statics)
}

// Prove produces a GKR proof
func (p *Prover) Prove(nCore int) Proof {
	// bG := p.circuit.bG
	nLayers := len(p.circuit.gates)
	ClaimsLeft := make([]fr.Element, nLayers)
	ClaimsRight := make([]fr.Element, nLayers)
	SumcheckProofs := make([]sumcheck.Proof, nLayers)

	// Initial round
	qPrime, q := GetInitialQPrimeAndQ(p.bN, p.circuit.bGs[nLayers])
	prover := p.InitialRoundSumcheckProver(qPrime, q)
	proof, qPrime, qL, qR, finalClaims := prover.ProveMultiThreaded(nCore)
	SumcheckProofs[nLayers-1] = proof
	ClaimsLeft[nLayers-1], ClaimsRight[nLayers-1] = finalClaims[0], finalClaims[1]

	for layer := nLayers - 2; layer >= 0; layer-- {

		// Compute the random linear comb of the claims
		var lambdaL fr.Element
		lambdaL.SetOne()
		lambdaR := common.GetChallenge([]fr.Element{ClaimsLeft[layer+1], ClaimsRight[layer+1]})
		claim := ClaimsRight[layer+1]
		claim.Mul(&claim, &lambdaR)
		claim.Add(&claim, &ClaimsLeft[layer+1])

		// Intermediate round sumcheck and update the GKR proof
		prover := p.IntermediateRoundsSumcheckProver(layer, qPrime, qL, qR, lambdaL, lambdaR)
		SumcheckProofs[layer], qPrime, qL, qR, finalClaims = prover.ProveMultiThreaded(nCore)
		ClaimsLeft[layer], ClaimsRight[layer] = finalClaims[0], finalClaims[1]
	}

	return Proof{
		SumcheckProofs: SumcheckProofs,
		ClaimsLeft:     ClaimsLeft,
		ClaimsRight:    ClaimsRight,
	}

}
