package gkr

import (
	"gkr-mimc/common"
	"gkr-mimc/sumcheck"

	"github.com/consensys/gurvy/bn256/fr"
)

// Verifier contains all the data relevant for the verifier algorithm of GKR
type Verifier struct {
	bN      int
	circuit Circuit
}

// NewVerifier constructs a new verifier object
func NewVerifier(bN int, circuit Circuit) Verifier {
	return Verifier{
		bN:      bN,
		circuit: circuit,
	}
}

// Verify returns true if the GKR proof is valid
func (v *Verifier) Verify(
	proof Proof,
	outputs, inputs []fr.Element,
) bool {

	nLayers := len(v.circuit.gates)
	inputsBKT := sumcheck.NewBookKeepingTable(inputs)
	outputsBKT := sumcheck.NewBookKeepingTable(outputs)

	qPrime, q := GetInitialQPrimeAndQ(v.bN, v.circuit.bGs[nLayers])
	var qL, qR []fr.Element

	claim := outputsBKT.Evaluate(
		append(append([]fr.Element{}, q...), qPrime...),
	)

	sumcheckVerifier := sumcheck.Verifier{}
	valid, nextQPrime, nextQL, nextQR, totalClaim := sumcheckVerifier.Verify(
		claim,
		proof.SumcheckProofs[nLayers-1],
		v.bN, v.circuit.bGs[nLayers-1],
	)

	if !valid {
		// The sumcheck proof is broken
		return false
	}

	evaluated := sumcheck.EvaluateCombinator(
		proof.ClaimsLeft[nLayers-1],
		proof.ClaimsRight[nLayers-1],
		EvalEq(qPrime, nextQPrime),
		v.circuit.gates[nLayers-1],
		v.evaluateStaticTables(nLayers-1, q, nextQL, nextQR),
	)

	if totalClaim != evaluated {
		// The sumcheck claim was inconsistent with the values claimed in the proof
		return false
	}

	for layer := nLayers - 2; layer >= 0; layer-- {
		// Compute the random linear comb of the claims
		var lambdaL fr.Element
		lambdaL.SetOne()
		lambdaR := common.GetChallenge([]fr.Element{proof.ClaimsLeft[layer+1], proof.ClaimsRight[layer+1]})
		claim = proof.ClaimsRight[layer+1]
		claim.Mul(&claim, &lambdaR)
		claim.Add(&claim, &proof.ClaimsLeft[layer+1])

		// Updates qL and qR values to initialize the next round
		qL = nextQL
		qR = nextQR
		qPrime = nextQPrime

		valid, nextQPrime, nextQL, nextQR, totalClaim = sumcheckVerifier.Verify(
			claim, proof.SumcheckProofs[layer],
			v.bN, v.circuit.bGs[layer],
		)
		if !valid {
			// The sumcheck proof is broken
			return false
		}

		if totalClaim != sumcheck.EvaluateCombinator(
			proof.ClaimsLeft[layer],
			proof.ClaimsRight[layer],
			EvalEq(qPrime, nextQPrime),
			v.circuit.gates[layer],
			v.evaluateStaticTablesLinCombs(layer, qL, qR, nextQL, nextQR, lambdaL, lambdaR),
		) {
			// The sumcheck claim was inconsistent with the values claimed in the proof
			return true
		}
	}

	// Final check => Check consistency with the last claims
	// on vL and vR with the values given as inputs
	//vL, vR from inputs
	actualVL, actualVR := inputsBKT.EvaluateLeftAndRight(nextQPrime, nextQL, nextQR)
	if actualVL != proof.ClaimsLeft[0] || actualVR != proof.ClaimsRight[0] {
		return false
	}

	return true
}

func (v *Verifier) evaluateStaticTables(layer int, q, nextQL, nextQR []fr.Element) []fr.Element {
	gens := v.circuit.staticTableGens[layer]
	evals := make([]fr.Element, len(gens))
	for i, f := range gens {
		tables := f(q)
		evals[i] = tables.Evaluate(append(nextQL, nextQR...))
	}
	return evals
}

func (v *Verifier) evaluateStaticTablesLinCombs(layer int, qL, qR, nextQL, nextQR []fr.Element, lambdaL, lambdaR fr.Element) []fr.Element {
	gens := v.circuit.staticTableGens[layer]
	evals := make([]fr.Element, len(gens))
	for i, f := range gens {
		tableLefts := f(qL)
		tableRights := f(qR)
		left := tableLefts.Evaluate(append(nextQL, nextQR...))
		right := tableRights.Evaluate(append(nextQL, nextQR...))
		right.Mul(&right, &lambdaR)
		left.Mul(&left, &lambdaL)
		left.Add(&left, &right)
		evals[i] = left
	}
	return evals
}
